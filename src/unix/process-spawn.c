/* Copyright Xiaomi, Inc. and other Node contributors. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#define __USE_GNU
#include "uv.h"
#include "internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <spawn.h>

#ifdef SIGCHLD
static void uv__chld(uv_signal_t* handle, int signum) {
  uv_process_t* process;
  uv_loop_t* loop;
  int exit_status;
  int term_signal;
  int status;
  pid_t pid;
  struct uv__queue pending;
  struct uv__queue* q;
  struct uv__queue* h;

  assert(signum == SIGCHLD);

  uv__queue_init(&pending);
  loop = handle->loop;

  h = &loop->process_handles;
  q = uv__queue_head(h);
  while (q != h) {
    process = uv__queue_data(q, uv_process_t, queue);
    q = uv__queue_next(q);

    do
      pid = waitpid(process->pid, &status, WNOHANG);
    while (pid == -1 && errno == EINTR);

    if (pid == 0)
      continue;

    if (pid == -1) {
      if (errno != ECHILD)
        assert(0);
      continue;
    }

    process->status = status;
    uv__queue_remove(&process->queue);
    uv__queue_insert_tail(&pending, &process->queue);
  }

  h = &pending;
  q = uv__queue_head(h);
  while (q != h) {
    process = uv__queue_data(q, uv_process_t, queue);
    q = uv__queue_next(q);

    uv__queue_remove(&process->queue);
    uv__queue_init(&process->queue);
    uv__handle_stop(process);

    if (process->exit_cb == NULL)
      continue;

    exit_status = 0;
    if (WIFEXITED(process->status))
      exit_status = WEXITSTATUS(process->status);

    term_signal = 0;
    if (WIFSIGNALED(process->status))
      term_signal = WTERMSIG(process->status);

    process->exit_cb(process, exit_status, term_signal);
  }
  assert(uv__queue_empty(&pending));
}


int uv__process_init(uv_loop_t* loop) {
  int err;

  err = uv_signal_init(loop, &loop->child_watcher);
  if (err)
    return err;
  uv__handle_unref(&loop->child_watcher);
  loop->child_watcher.flags |= UV_HANDLE_INTERNAL;
  return 0;
}
#endif

/*
 * Used for initializing stdio streams like options.stdin_stream. Returns
 * zero on success. See also the cleanup section in uv_spawn().
 */
static int uv__process_init_stdio(uv_stdio_container_t* container, int fds[2]) {
  int mask;
  int fd;

  mask = UV_IGNORE | UV_CREATE_PIPE | UV_INHERIT_FD | UV_INHERIT_STREAM;

  switch (container->flags & mask) {
  case UV_IGNORE:
    return 0;

  case UV_CREATE_PIPE:
    assert(container->data.stream != NULL);
    if (container->data.stream->type != UV_NAMED_PIPE)
      return UV_EINVAL;
    else
      return uv_pipe(fds, 0, 0);

  case UV_INHERIT_FD:
  case UV_INHERIT_STREAM:
    if (container->flags & UV_INHERIT_FD)
      fd = container->data.fd;
    else
      fd = uv__stream_fd(container->data.stream);

    if (fd == -1)
      return UV_EINVAL;

    fds[0] = fds[1] = fd;
    return 0;

  default:
    assert(0 && "Unexpected flags");
    return UV_EINVAL;
  }
}


static int uv__process_open_stream(uv_stdio_container_t* container,
                                   int pipefds[2]) {
  int flags;

  if (!(container->flags & UV_CREATE_PIPE) || pipefds[0] < 0)
    return 0;

  uv__nonblock(pipefds[0], 1);

  flags = 0;
  if (container->flags & UV_WRITABLE_PIPE)
    flags |= UV_HANDLE_READABLE;
  if (container->flags & UV_READABLE_PIPE)
    flags |= UV_HANDLE_WRITABLE;

  return uv__stream_open(container->data.stream, pipefds[0], flags);
}


static void uv__process_close_stream(uv_stdio_container_t* container) {
  if (!(container->flags & UV_CREATE_PIPE)) return;
  uv__stream_close(container->data.stream);
}


static int uv__process_child_spawn(const uv_process_options_t* options,
                                   int stdio_count,
                                   int (*pipes)[2],
                                   pid_t *pid) {
  posix_spawn_file_actions_t file_actions;
  posix_spawnattr_t attr;
  sigset_t set;
  int use_fd;
  int flags;
  int err;
  int fd;

  posix_spawn_file_actions_init(&file_actions);
  posix_spawnattr_init(&attr);
#ifdef DEF_THREADPOOL_STACKSIZE
  posix_spawnattr_setstacksize(&attr, DEF_THREADPOOL_STACKSIZE);
#endif

  /* Reset signal disposition and mask */
  flags = POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK;

  sigfillset(&set);
  posix_spawnattr_setsigdefault(&attr, &set);

  sigemptyset(&set);
  posix_spawnattr_setsigmask(&attr, &set);

  if (options->flags & UV_PROCESS_DETACHED)
    flags |= POSIX_SPAWN_SETSID;

  /* First duplicate low numbered fds, since it's not safe to duplicate them,
   * they could get replaced. Example: swapping stdout and stderr; without
   * this fd 2 (stderr) would be duplicated into fd 1, thus making both
   * stdout and stderr go to the same fd, which was not the intention. */
  for (fd = 0; fd < stdio_count; fd++) {
    use_fd = pipes[fd][1];
    if (use_fd < 0 || use_fd >= fd)
      continue;
    pipes[fd][1] = fcntl(use_fd, F_DUPFD, stdio_count);
    if (pipes[fd][1] == -1) {
      err = errno;
      goto error;
    }
  }

  for (fd = 0; fd < stdio_count; fd++) {
    use_fd = pipes[fd][1];

    if (use_fd < 0) {
      if (fd >= 3)
        continue;
      else {
        /* redirect stdin, stdout and stderr to /dev/null even if UV_IGNORE is
         * set
         */
        use_fd = open("/dev/null", fd == 0 ? O_RDONLY : O_RDWR);
        pipes[fd][1] = use_fd;

        if (use_fd < 0) {
          err = errno;
          goto error;
        }
      }
    }

    if (fd == use_fd)
      uv__cloexec(use_fd, 0);
    else
      posix_spawn_file_actions_adddup2(&file_actions, use_fd, fd);

    if (fd <= 2)
      uv__nonblock_fcntl(use_fd, 0);
  }

  if (options->flags & UV_PROCESS_SETUID) {
    err = options->uid ? ENOTSUP : EPERM;
    goto error;
  }

  if (options->flags & UV_PROCESS_SETGID) {
    if (options->gid == 0) {
      err = EPERM;
      goto error;
    }

    posix_spawnattr_setpgroup(&attr, options->gid);
    flags |= POSIX_SPAWN_SETPGROUP;
  }

  posix_spawnattr_setflags(&attr, flags);
  err = posix_spawn(pid, options->file, &file_actions, &attr,
                    options->args, options->env ? options->env : environ);

error:
  for (fd = 0; fd < stdio_count; fd++) {
    if (pipes[fd][1] >= 0 && pipes[fd][1] != pipes[fd][0]) {
      close(pipes[fd][1]);
      pipes[fd][1] = -1;
    }
  }

  posix_spawn_file_actions_destroy(&file_actions);
  posix_spawnattr_destroy(&attr);
  return UV__ERR(err);
}


int uv_spawn(uv_loop_t* loop,
             uv_process_t* process,
             const uv_process_options_t* options) {
  int pipes_storage[8][2];
  int (*pipes)[2];
  int stdio_count;
  pid_t pid;
  int err;
  int i;

  assert(options->file != NULL);
  assert(!(options->flags & ~(UV_PROCESS_DETACHED |
                              UV_PROCESS_SETGID |
                              UV_PROCESS_SETUID |
                              UV_PROCESS_WINDOWS_HIDE |
                              UV_PROCESS_WINDOWS_HIDE_CONSOLE |
                              UV_PROCESS_WINDOWS_HIDE_GUI |
                              UV_PROCESS_WINDOWS_VERBATIM_ARGUMENTS)));

  uv__handle_init(loop, (uv_handle_t*)process, UV_PROCESS);
  uv__queue_init(&process->queue);

  stdio_count = options->stdio_count;
  if (stdio_count < 3)
    stdio_count = 3;

  err = UV_ENOMEM;
  pipes = pipes_storage;
  if (stdio_count > (int)ARRAY_SIZE(pipes_storage))
    pipes = uv__malloc(stdio_count * sizeof(*pipes));

  if (pipes == NULL)
    goto error;

  for (i = 0; i < stdio_count; i++) {
    pipes[i][0] = -1;
    pipes[i][1] = -1;
  }

  for (i = 0; i < options->stdio_count; i++) {
    err = uv__process_init_stdio(options->stdio + i, pipes[i]);
    if (err)
      goto error;
  }

#ifdef SIGCHLD
  uv_signal_start(&loop->child_watcher, uv__chld, SIGCHLD);
#endif

  err = uv__process_child_spawn(options, stdio_count, pipes, &pid);
  if (err)
    goto error;

  for (i = 0; i < options->stdio_count; i++) {
    err = uv__process_open_stream(options->stdio + i, pipes[i]);
    if (err == 0)
      continue;

    while (i--)
      uv__process_close_stream(options->stdio + i);

    goto error;
  }

  uv__queue_insert_tail(&loop->process_handles, &process->queue);
  uv__handle_start(process);

  process->status = 0;
  process->pid = pid;
  process->exit_cb = options->exit_cb;

  if (pipes != pipes_storage)
    uv__free(pipes);

  return 0;

error:
  if (pipes != NULL) {
    for (i = 0; i < stdio_count; i++) {
      if (i < options->stdio_count)
        if (options->stdio[i].flags & (UV_INHERIT_FD | UV_INHERIT_STREAM))
          continue;
      if (pipes[i][0] != -1)
        uv__close_nocheckstdio(pipes[i][0]);
      if (pipes[i][1] != -1)
        uv__close_nocheckstdio(pipes[i][1]);
    }

    if (pipes != pipes_storage)
      uv__free(pipes);
  }

  return err;
}

int uv_process_kill(uv_process_t* process, int signum) {
  return uv_kill(process->pid, signum);
}

int uv_kill(int pid, int signum) {
  if (kill(pid, signum))
    return UV__ERR(errno);
  else
    return 0;
}

void uv__process_close(uv_process_t* handle) {
  uv__queue_remove(&handle->queue);
  uv__handle_stop(handle);
  if (uv__queue_empty(&handle->loop->process_handles))
    uv_signal_stop(&handle->loop->child_watcher);
}
