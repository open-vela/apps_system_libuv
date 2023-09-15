/* Copyright Joyent, Inc. and other Node contributors. All rights reserved.
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

#ifndef UV_GLOBAL_H
#define UV_GLOBAL_H

#include "uv.h"

#ifndef DEF_THREADPOOL_SIZE
# define DEF_THREADPOOL_SIZE 4
#endif

#if !defined(_WIN32)
typedef struct {
  uv_signal_t* handle;
  int signum;
} uv__signal_msg_t;

RB_HEAD(uv__signal_tree_s, uv_signal_s);
#endif

typedef struct {
  /* Member in threadpool.c */
  uv_once_t once;
  uv_cond_t cond;
  uv_mutex_t mutex;
  unsigned int idle_threads;
  unsigned int slow_io_work_running;
  unsigned int nthreads;
  uv_thread_t* threads;
  uv_thread_t default_threads[DEF_THREADPOOL_SIZE];
  struct uv__queue exit_message;
  struct uv__queue wq;
  struct uv__queue run_slow_work_message;
  struct uv__queue slow_io_pending_wq;
  /* Member in uv-common.c */
  int was_shutdown;
  uv_loop_t default_loop_struct;
  uv_loop_t* default_loop_ptr;
#if !defined(_WIN32)
  /* Member in signal.c */
  uv_once_t uv__signal_global_init_guard;
  struct uv__signal_tree_s uv__signal_tree;
  int uv__signal_lock_pipefd[2];
#endif
} uv__global_t;

uv__global_t* uv__global_get(void);

/* Used in threadpool.c */

#define once uv__global_get()->once
#define cond uv__global_get()->cond
#define mutex uv__global_get()->mutex
#define idle_threads uv__global_get()->idle_threads
#define slow_io_work_running uv__global_get()->slow_io_work_running
#define nthreads uv__global_get()->nthreads
#define threads uv__global_get()->threads
#define default_threads uv__global_get()->default_threads
#define exit_message uv__global_get()->exit_message
#define lwq uv__global_get()->wq
#define run_slow_work_message uv__global_get()->run_slow_work_message
#define slow_io_pending_wq uv__global_get()->slow_io_pending_wq

/* Used in uv-common.c */

#define was_shutdown uv__global_get()->was_shutdown
#define default_loop_struct uv__global_get()->default_loop_struct
#define default_loop_ptr uv__global_get()->default_loop_ptr

#if !defined(_WIN32)
/* Used in signal.c */

#define uv__signal_global_init_guard uv__global_get()->uv__signal_global_init_guard
#define uv__signal_tree uv__global_get()->uv__signal_tree
#define uv__signal_lock_pipefd uv__global_get()->uv__signal_lock_pipefd
#endif

#endif
