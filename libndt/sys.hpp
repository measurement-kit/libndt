#ifndef MEASUREMENT_KIT_LIBNDT_SYS_HPP
#define MEASUREMENT_KIT_LIBNDT_SYS_HPP

// Dependencies (libc)
// ```````````````````

#ifndef LIBNDT_NO_INLINE_IMPL
namespace measurement_kit {
namespace libndt {

#ifdef _WIN32
#define LIBNDT_AS_OS_BUFFER(b) ((char *)b)
#define LIBNDT_AS_OS_BUFFER_LEN(n) ((int)n)
#define LIBNDT_OS_SSIZE_MAX INT_MAX
#define LIBNDT_AS_OS_OPTION_VALUE(x) ((char *)x)
#else
#define LIBNDT_AS_OS_BUFFER(b) ((char *)b)
#define LIBNDT_AS_OS_BUFFER_LEN(n) ((size_t)n)
#define LIBNDT_OS_SSIZE_MAX SSIZE_MAX
#define LIBNDT_AS_OS_OPTION_VALUE(x) ((void *)x)
#endif

int Client::sys_get_last_error() const noexcept {
#ifdef _WIN32
  return GetLastError();
#else
  return errno;
#endif
}

void Client::sys_set_last_error(int err) const noexcept {
#ifdef _WIN32
  SetLastError(err);
#else
  errno = err;
#endif
}

int Client::sys_getaddrinfo(const char *domain, const char *port,
                            const addrinfo *hints, addrinfo **res) noexcept {
  return ::getaddrinfo(domain, port, hints, res);
}

int Client::sys_getnameinfo(const sockaddr *sa, socklen_t salen, char *host,
                            socklen_t hostlen, char *serv, socklen_t servlen,
                            int flags) noexcept {
  return ::getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
}

void Client::sys_freeaddrinfo(addrinfo *aip) noexcept { ::freeaddrinfo(aip); }

Socket Client::sys_socket(int domain, int type, int protocol) noexcept {
  return (Socket)::socket(domain, type, protocol);
}

int Client::sys_connect(Socket fd, const sockaddr *sa, socklen_t len) noexcept {
  return ::connect(fd, sa, len);
}

Ssize Client::sys_recv(Socket fd, void *base, Size count) const noexcept {
  if (count > LIBNDT_OS_SSIZE_MAX) {
    sys_set_last_error(OS_EINVAL);
    return -1;
  }
  int flags = 0;
#ifdef LIBNDT_HAVE_MSG_NOSIGNAL
  // On Linux systems this flag prevents socket ops from raising SIGPIPE.
  flags |= MSG_NOSIGNAL;
#endif
  return (Ssize)::recv(fd, LIBNDT_AS_OS_BUFFER(base), LIBNDT_AS_OS_BUFFER_LEN(count), flags);
}

Ssize Client::sys_send(Socket fd, const void *base, Size count) const noexcept {
  if (count > LIBNDT_OS_SSIZE_MAX) {
    sys_set_last_error(OS_EINVAL);
    return -1;
  }
  int flags = 0;
#ifdef LIBNDT_HAVE_MSG_NOSIGNAL
  // On Linux systems this flag prevents socket ops from raising SIGPIPE.
  flags |= MSG_NOSIGNAL;
#endif
  return (Ssize)::send(fd, LIBNDT_AS_OS_BUFFER(base), LIBNDT_AS_OS_BUFFER_LEN(count), flags);
}

int Client::sys_shutdown(Socket fd, int shutdown_how) noexcept {
  return ::shutdown(fd, shutdown_how);
}

int Client::sys_closesocket(Socket fd) noexcept {
#ifdef _WIN32
  return ::closesocket(fd);
#else
  return ::close(fd);
#endif
}

#ifdef _WIN32
int Client::sys_poll(LPWSAPOLLFD fds, ULONG nfds, INT timeout) const noexcept {
  return ::WSAPoll(fds, nfds, timeout);
}
#else
int Client::sys_poll(pollfd *fds, nfds_t nfds, int timeout) const noexcept {
  return ::poll(fds, nfds, timeout);
}
#endif

long long Client::sys_strtonum(const char *s, long long minval,
                               long long maxval, const char **errp) noexcept {
  return strtonum(s, minval, maxval, errp);
}

#ifdef _WIN32
int Client::sys_ioctlsocket(Socket s, long cmd, u_long *argp) noexcept {
  return ::ioctlsocket(s, cmd, argp);
}
#else
int Client::sys_fcntl(Socket s, int cmd) noexcept { return ::fcntl(s, cmd); }
int Client::sys_fcntl(Socket s, int cmd, int arg) noexcept {
  return ::fcntl(s, cmd, arg);
}
#endif

int Client::sys_getsockopt(Socket socket, int level, int name, void *value,
                           socklen_t *len) noexcept {
  return ::getsockopt(socket, level, name, LIBNDT_AS_OS_OPTION_VALUE(value), len);
}

}  // namespace libndt
}  // namespace measurement_kit
#endif  // LIBNDT_NO_INLINE_IMPL
#endif
