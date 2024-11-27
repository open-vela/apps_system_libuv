/* Copyright Xiaomi, Inc. and other Node contributors. All rights reserved.
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

/* We lean on the fact that POLL{IN,OUT,ERR,HUP} correspond with their
 * EPOLL* counterparts.  We use the POLL* variants in this file because that
 * is what libuv uses elsewhere.
 */

#include <nuttx/arch.h>
#include <nuttx/tls.h>

#include "internal.h"
#include "uv.h"
#include "uv-global.h"

#include <ifaddrs.h>
#include <malloc.h>
#include <net/if.h>
#include <pthread.h>
#include <sys/sysinfo.h>
#include <unistd.h>


int uv_exepath(char* buffer, size_t* size) {
  int ret;
  ret = pthread_getname_np(getpid(), buffer, *size);
  if (ret == 0)
    {
      *size = strlen(buffer);
    }

  return UV__ERR(ret);
}

char** uv_setup_args(int argc, char** argv) {
  return argv;
}

void uv__process_title_cleanup(void) {
}

int uv_set_process_title(const char* title) {
  return UV__ERR(pthread_setname_np(getpid(), title));
}

int uv_get_process_title(char* buffer, size_t size) {
  return UV__ERR(pthread_getname_np(getpid(), buffer, size));
}

uint64_t uv_get_constrained_memory(void) {
  return 0;  /* Memory constraints are unknown. */
}

uint64_t uv_get_available_memory(void) {
  return uv_get_free_memory();
}

int uv_resident_set_memory(size_t* rss) {
  struct sysinfo info;
  int ret;

  ret = sysinfo(&info);
  if (ret >= 0)
    {
      *rss = (info.totalram - info.freeram) * info.mem_unit;
    }
  else
    {
      ret = UV__ERR(errno);
    }

  return ret;
}

int uv_uptime(double* uptime) {
  struct sysinfo info;
  int ret;


  ret = sysinfo(&info);
  if (ret >= 0)
    {
      *uptime = info.uptime;
    }
  else
    {
      ret = UV__ERR(errno);
    }

  return ret;
}

int uv_cpu_info(uv_cpu_info_t** cpu_infos, int* count) {
  *count = sysconf(_SC_NPROCESSORS_ONLN);

  /* sysconf returns -1 on failure, check it before allocating memory */
  if (*count == -1) {
    return UV_ENOSYS;
  }

  *cpu_infos = uv__calloc(*count, sizeof(uv_cpu_info_t));
  if (!*cpu_infos) {
    return UV_ENOMEM;
  }

  return 0;
}

#ifndef CONFIG_PSEUDOFS_SOFTLINKS
int symlink(const char *path1, const char *path2)
{
  return ERROR;
}

ssize_t readlink(const char *path, char *buf, size_t bufsize)
{
  return ERROR;
}

int link(const char *path1, const char *path2)
{
  return ERROR;
}
#endif

#ifndef CONFIG_LIBC_DLFCN
int uv_dlopen(const char* filename, uv_lib_t* lib) {
  return UV_ENOSYS;
}

void uv_dlclose(uv_lib_t* lib) {
}

int uv_dlsym(uv_lib_t* lib, const char* name, void** ptr) {
  return UV_ENOSYS;
}

const char* uv_dlerror(const uv_lib_t* lib) {
  return "dlopen() is not supported on this platform";
}
#endif

/* This section is used with LIBC_NETDB disabled, which means the
 * getaddrinfo.c/getnameinfo.c will not be compiled.
 *
 * Use the dummy implementation for better footprint.
 */

#ifndef CONFIG_LIBC_NETDB
int uv_getaddrinfo(uv_loop_t* loop,
                   uv_getaddrinfo_t* req,
                   uv_getaddrinfo_cb getaddrinfo_cb,
                   const char* node,
                   const char* service,
                   const struct addrinfo* hints) {
  return UV_ENOTSUP;
}

void uv_freeaddrinfo(struct addrinfo* ai) {
  ASSERT(false);
}

int uv_getnameinfo(uv_loop_t* loop,
                   uv_getnameinfo_t* req,
                   uv_getnameinfo_cb getnameinfo_cb,
                   const struct sockaddr* addr,
                   int flags) {
  return UV_ENOTSUP;
}

int uv_if_indextoname(unsigned int ifindex,
                      char* buffer,
                      size_t* size) {
  return UV_ENOTSUP;
}

int uv_if_indextoiid(unsigned int ifindex,
                     char* buffer,
                     size_t* size) {
  return UV_ENOTSUP;
}
#endif

/* This section is used with LIBC_NETDB enabled but NETDEV_IFINDEX disabled,
 * if_nametoindex/if_indextoname called from uv-common.c, so should provide
 * dummy implementation for them.
 */

#ifndef CONFIG_NETDEV_IFINDEX
unsigned int if_nametoindex(const char *ifname) {
  return 0;
}

FAR char *if_indextoname(unsigned int ifindex, char *ifname)
{
  return NULL;
}

int uv_interface_addresses(uv_interface_address_t** addresses, int* count) {
  return UV_ENOSYS;
}

void uv_free_interface_addresses(uv_interface_address_t* addresses, int count) {
}
#else
static int uv__ifaddr_exclude(struct ifaddrs *ent) {
  if (!((ent->ifa_flags & IFF_UP) && (ent->ifa_flags & IFF_RUNNING)))
    return 1;
  if (ent->ifa_addr == NULL)
    return 1;
  return 0;
}

int uv_interface_addresses(uv_interface_address_t** addresses, int* count) {
  struct ifaddrs* addrs;
  struct ifaddrs* ent;
  uv_interface_address_t* address;

  *count = 0;
  *addresses = NULL;

  if (getifaddrs(&addrs) != 0)
    return UV__ERR(errno);

  /* Count the number of interfaces */
  for (ent = addrs; ent != NULL; ent = ent->ifa_next) {
    if (uv__ifaddr_exclude(ent))
      continue;
    (*count)++;
  }

  if (*count == 0) {
    freeifaddrs(addrs);
    return 0;
  }

  /* Make sure the memory is initiallized to zero using calloc() */
  *addresses = uv__calloc(*count, sizeof(**addresses));
  if (*addresses == NULL) {
    freeifaddrs(addrs);
    return UV_ENOMEM;
  }

  address = *addresses;
  for (ent = addrs; ent != NULL; ent = ent->ifa_next) {
    if (uv__ifaddr_exclude(ent))
      continue;

    address->name = uv__strdup(ent->ifa_name);

    if (ent->ifa_addr->sa_family == AF_INET6) {
      address->address.address6 = *((struct sockaddr_in6*) ent->ifa_addr);
    } else {
      address->address.address4 = *((struct sockaddr_in*) ent->ifa_addr);
    }

    if (ent->ifa_netmask) {
      if (ent->ifa_netmask->sa_family == AF_INET6) {
        address->netmask.netmask6 = *((struct sockaddr_in6*) ent->ifa_netmask);
      } else {
        address->netmask.netmask4 = *((struct sockaddr_in*) ent->ifa_netmask);
      }
    }

    if (ent->ifa_data) {
      struct sockaddr* addr = ent->ifa_data;
      memcpy(address->phys_addr, addr->sa_data, sizeof(address->phys_addr));
    }

    address->is_internal = !strcmp(address->name, "lo");
    address++;
  }

  freeifaddrs(addrs);
  return 0;
}

void uv_free_interface_addresses(uv_interface_address_t* addresses, int count) {
  int i;

  for (i = 0; i < count; i++) {
    uv__free(addresses[i].name);
  }

  uv__free(addresses);
}
#endif

#ifndef CONFIG_NET_SOCKOPTS
int getsockopt(int sockfd, int level, int option, void *value, socklen_t *value_len) {
  if (option == SO_ERROR) {
    *(int *)value = UV_ENOTSUP;
  }

  return UV_ENOTSUP;
}
#endif

#ifndef CONFIG_NET
int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  return UV_ENOTSUP;
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags) {
  return UV_ENOTSUP;
}

ssize_t sendmsg(int sockfd, struct msghdr *msg, int flags) {
  return UV_ENOTSUP;
}

int shutdown(int sockfd, int how) {
  return UV_ENOTSUP;
}
#endif

#ifndef CONFIG_NET_TCP
int uv_socketpair(int type,
                  int protocol,
                  uv_os_sock_t socket_vector[2],
                  int flags0,
                  int flags1) {
  return UV_ENOTSUP;
}

int uv_tcp_init(uv_loop_t* loop, uv_tcp_t* handle) {
  return UV_ENOTSUP;
}

int uv_tcp_init_ex(uv_loop_t* loop, uv_tcp_t* handle, unsigned int flags) {
  return UV_ENOTSUP;
}

int uv_tcp_open(uv_tcp_t* handle, uv_os_sock_t sock) {
  return UV_ENOTSUP;
}

int uv_tcp_nodelay(uv_tcp_t* handle, int on) {
  return UV_ENOTSUP;
}

int uv_tcp_keepalive(uv_tcp_t* handle, int enable, unsigned int delay) {
  return UV_ENOTSUP;
}

int uv_tcp_getsockname(const uv_tcp_t* handle,
                       struct sockaddr* name,
                       int* namelen) {
  return UV_ENOTSUP;
}

int uv_tcp_getpeername(const uv_tcp_t* handle,
                       struct sockaddr* name,
                       int* namelen) {
  return UV_ENOTSUP;
}

int uv_tcp_close_reset(uv_tcp_t* handle, uv_close_cb close_cb) {
  return UV_ENOTSUP;
}

int uv__tcp_listen(uv_tcp_t* tcp, int backlog, uv_connection_cb cb) {
  return UV_ENOTSUP;
}

void uv__tcp_close(uv_tcp_t* handle) {
}

int uv__tcp_nodelay(int fd, int on) {
  return UV_ENOTSUP;
}

int uv__tcp_connect(uv_connect_t* req,
                    uv_tcp_t* handle,
                    const struct sockaddr* addr,
                    unsigned int addrlen,
                    uv_connect_cb cb) {
  return UV_ENOTSUP;
}

int uv__tcp_bind(uv_tcp_t* tcp,
                 const struct sockaddr* addr,
                 unsigned int addrlen,
                 unsigned int flags) {
  return UV_ENOTSUP;
}

int uv__tcp_keepalive(int fd, int on, unsigned int delay) {
  return UV_ENOTSUP;
}
#endif

#ifndef CONFIG_NET_UDP
int uv_udp_open(uv_udp_t* handle, uv_os_sock_t sock) {
  return UV_ENOTSUP;
}

int uv_udp_getsockname(const uv_udp_t* handle,
                       struct sockaddr* name,
                       int* namelen) {
  return UV_ENOTSUP;
}

int uv__udp_init_ex(uv_loop_t* loop,
                    uv_udp_t* handle,
                    unsigned flags,
                    int domain) {
  return UV_ENOTSUP;
}

int uv__udp_bind(uv_udp_t* handle,
                 const struct sockaddr* addr,
                 unsigned int addrlen,
                 unsigned int flags) {
  return UV_ENOTSUP;
}

int uv__udp_connect(uv_udp_t* handle,
                    const struct sockaddr* addr,
                    unsigned int addrlen) {
  return UV_ENOTSUP;
}

int uv__udp_send(uv_udp_send_t* req,
                 uv_udp_t* handle,
                 const uv_buf_t bufs[],
                 unsigned int nbufs,
                 const struct sockaddr* addr,
                 unsigned int addrlen,
                 uv_udp_send_cb send_cb) {
  return UV_ENOTSUP;
}

int uv__udp_try_send(uv_udp_t* handle,
                     const uv_buf_t bufs[],
                     unsigned int nbufs,
                     const struct sockaddr* addr,
                     unsigned int addrlen) {
  return UV_ENOTSUP;
}

int uv__udp_recv_start(uv_udp_t* handle, uv_alloc_cb alloccb,
                       uv_udp_recv_cb recv_cb) {
  return UV_ENOTSUP;
}

int uv__udp_recv_stop(uv_udp_t* handle) {
  return UV_ENOTSUP;
}

int uv__udp_disconnect(uv_udp_t* handle) {
  return UV_ENOTSUP;
}

void uv__udp_close(uv_udp_t* handle) {
}

void uv__udp_finish_close(uv_udp_t* handle) {
}

int uv_udp_set_broadcast(uv_udp_t* handle, int on) {
  return UV_ENOTSUP;
}

int uv_udp_set_ttl(uv_udp_t* handle, int ttl) {
  return UV_ENOTSUP;
}

int uv_udp_set_multicast_loop(uv_udp_t* handle, int on) {
  return UV_ENOTSUP;
}

int uv_udp_set_multicast_interface(uv_udp_t* handle, const char* interface_addr) {
  return UV_ENOTSUP;
}

int uv_udp_set_multicast_ttl(uv_udp_t* handle, int ttl) {
  return UV_ENOTSUP;
}

int uv_udp_set_membership(uv_udp_t* handle,
                          const char* multicast_addr,
                          const char* interface_addr,
                          uv_membership membership) {
  return UV_ENOTSUP;
}

int uv_udp_set_source_membership(uv_udp_t* handle,
                                 const char* multicast_addr,
                                 const char* interface_addr,
                                 const char* source_addr,
                                 uv_membership membership) {
  return UV_ENOTSUP;
}

int uv_udp_getpeername(const uv_udp_t* handle,
                       struct sockaddr* name,
                       int* namelen) {
  return UV_ENOTSUP;
}

int uv_udp_using_recvmmsg(const uv_udp_t* handle) {
  return UV_ENOTSUP;
}
#endif

#if CONFIG_TLS_TASK_NELEM == 0
#  error "libuv depends on CONFIG_TLS_TASK_NELEM, please enable it by menuconfig"
#endif

#undef once
#undef uv__signal_global_init_guard
#undef uv__signal_lock_pipefd

static void uv__global_free(void* global) {
  if (global) {
    uv_library_shutdown();
    uv__free(global);
  }
}

/* TLS index for uv_global_t */
static int global_tls_index;

/* Init once only by uv_once */
static void uv__global_index_alloc(void) {
  global_tls_index = task_tls_alloc(uv__global_free);

  ASSERT(global_tls_index >= 0);
}

uv__global_t* uv__global_get(void) {
  static uv_once_t once = UV_ONCE_INIT;
  uv__global_t* global = NULL;

  uv_once(&once, uv__global_index_alloc);

  global = (uv__global_t*)task_tls_get_value(global_tls_index);
  if (global == NULL) {
    global = (uv__global_t*)uv__calloc(1, sizeof(uv__global_t));
    if (global) {
      uv_once_t template = UV_ONCE_INIT;

      global->once = template;
      global->uv__signal_global_init_guard = template;
      global->uv__signal_lock_pipefd[0] = -1;
      global->uv__signal_lock_pipefd[1] = -1;
      task_tls_set_value(global_tls_index, (uintptr_t)global);
    }
  }

  ASSERT(global != NULL);
  return global;
}

#ifndef CONFIG_FS_NOTIFY
int inotify_init(void)
{
  return UV_ENOTSUP;
}

int inotify_init1(int flags)
{
  return UV_ENOTSUP;
}

int inotify_add_watch(int fd, FAR const char *pathname, uint32_t mask)
{
  return UV_ENOTSUP;
}

int inotify_rm_watch(int fd, int wd)
{
  return UV_ENOTSUP;
}
#endif
