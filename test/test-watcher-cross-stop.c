/* Copyright Joyent, Inc. and other Node contributors. All rights reserved.
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

#include "uv.h"
#include "task.h"

#include <string.h>
#include <errno.h>

/* NOTE: Number should be big enough to trigger this problem */
#if defined(__CYGWIN__) || defined(__MSYS__) || defined(__PASE__) || defined(__NuttX__)
/* Cygwin crashes or hangs in socket() with too many AF_INET sockets.  */
/* IBMi PASE timeout with too many AF_INET sockets.  */
#  define SOCKET_NUM 125
#else
#  define SOCKET_NUM 2500
#endif
static uv_udp_t* sockets;
static uv_udp_send_t* reqs;
static char slab[1];
static unsigned int recv_cb_called;
static unsigned int send_cb_called;
static unsigned int close_cb_called;

static void alloc_cb(uv_handle_t* handle, size_t size, uv_buf_t* buf) {
  buf->base = slab;
  buf->len = sizeof(slab);
}


static void recv_cb(uv_udp_t* handle,
                    ssize_t nread,
                    const uv_buf_t* buf,
                    const struct sockaddr* addr,
                    unsigned flags) {
  recv_cb_called++;
}


static void send_cb(uv_udp_send_t* req, int status) {
  send_cb_called++;
}


static void close_cb(uv_handle_t* handle) {
  close_cb_called++;
}


TEST_IMPL(watcher_cross_stop) {
#if defined(__MVS__)
  RETURN_SKIP("zOS does not allow address or port reuse when using UDP sockets");
#endif
  uv_loop_t* loop = uv_default_loop();
  unsigned int i;
  struct sockaddr_in addr;
  uv_buf_t buf;
  char big_string[1024];

  TEST_FILE_LIMIT(SOCKET_NUM + 32);

  sockets = (uv_udp_t*)malloc(sizeof(uv_udp_t) * SOCKET_NUM);
  ASSERT(sockets != NULL);

  reqs = (uv_udp_send_t*)malloc(sizeof(uv_udp_send_t) * SOCKET_NUM);
  ASSERT(reqs != NULL);

  ASSERT(0 == uv_ip4_addr("127.0.0.1", TEST_PORT, &addr));
  memset(big_string, 'A', sizeof(big_string));
  buf = uv_buf_init(big_string, sizeof(big_string));

  for (i = 0; i < SOCKET_NUM; i++) {
    ASSERT(0 == uv_udp_init(loop, &sockets[i]));
    ASSERT(0 == uv_udp_bind(&sockets[i],
                            (const struct sockaddr*) &addr,
                            UV_UDP_REUSEADDR));
    ASSERT(0 == uv_udp_recv_start(&sockets[i], alloc_cb, recv_cb));
    ASSERT(0 == uv_udp_send(&reqs[i],
                            &sockets[i],
                            &buf,
                            1,
                            (const struct sockaddr*) &addr,
                            send_cb));
  }

  while (recv_cb_called == 0)
    uv_run(loop, UV_RUN_ONCE);

  for (i = 0; i < SOCKET_NUM; i++)
    uv_close((uv_handle_t*) &sockets[i], close_cb);

  ASSERT(recv_cb_called > 0);

  uv_run(loop, UV_RUN_DEFAULT);

  free(sockets);
  free(reqs);

  ASSERT(SOCKET_NUM == send_cb_called);
  ASSERT(SOCKET_NUM == close_cb_called);

  MAKE_VALGRIND_HAPPY(loop);
  return 0;
}
