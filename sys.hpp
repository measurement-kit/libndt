// Part of Measurement Kit <https://measurement-kit.github.io/>.
// Measurement Kit is free software under the BSD license. See AUTHORS
// and LICENSE for more information on the copying conditions.
#ifndef MEASUREMENT_KIT_LIBNDT_SYS_HPP
#define MEASUREMENT_KIT_LIBNDT_SYS_HPP

// libndt/sys.hpp - system dependent routines

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <unistd.h>
#endif

#include <limits.h>
#include <stdlib.h>
#include <stdint.h>

namespace measurement_kit {
namespace libndt {

// Size is our definition of size
using Size = uint64_t;

// SizeMax is the maximum value that Size could have
constexpr Size SizeMax = UINT64_MAX;

// Ssize is the signed size (like ssize_t)
using Ssize = int64_t;

// Socket is the definition of socket
#ifdef _WIN32
using Socket = SOCKET;
#else
using Socket = int;
#endif

// is_socket_valid tells you whether a socket is valid
constexpr bool is_socket_valid(Socket s) noexcept {
#ifdef _WIN32
  return s != INVALID_SOCKET;
#else
  return s >= 0;
#endif
}

// LIBNDT_OS_EINVAL is a portable EINVAL
#ifdef _WIN32
#define LIBNDT_OS_EINVAL WSAEINVAL
#else
#define LIBNDT_OS_EINVAL EINVAL
#endif

// Sys contains wrappers for system facilities we use in libndt
class Sys {
 public:
  // Access the value of errno in a portable way.
  virtual int get_last_error() const noexcept;

  // Set the value of errno in a portable way.
  virtual void set_last_error(int err) const noexcept;

  // getaddrinfo() wrapper that can be mocked in tests.
  virtual int getaddrinfo(
      const char *domain, const char *port, const addrinfo *hints,
      addrinfo **res) const noexcept;

  // getnameinfo() wrapper that can be mocked in tests.
  virtual int getnameinfo(
      const sockaddr *sa, socklen_t salen, char *host, socklen_t hostlen,
      char *serv, socklen_t servlen, int flags) const noexcept;

  // freeaddrinfo() wrapper that can be mocked in tests.
  virtual void freeaddrinfo(addrinfo *aip) const noexcept;

  // socket() wrapper that can be mocked in tests.
  virtual Socket socket(int domain, int type, int protocol) const noexcept;

  // connect() wrapper that can be mocked in tests.
  virtual int connect(
      Socket fd, const sockaddr *sa, socklen_t n) const noexcept;

  // recv() wrapper that can be mocked in tests.
  virtual Ssize recv(Socket fd, void *base, Size count) const noexcept;

  // send() wrapper that can be mocked in tests.
  virtual Ssize send(
    Socket fd, const void *base, Size count) const noexcept;

  // shutdown() wrapper that can be mocked in tests.
  virtual int shutdown(Socket fd, int shutdown_how) const noexcept;

  // Portable wrapper for closing a socket descriptor.
  virtual int closesocket(Socket fd) const noexcept;

  // poll() wrapper that can be mocked in tests.
#ifdef _WIN32
  virtual int poll(LPWSAPOLLFD fds, ULONG nfds, INT timeout) const noexcept;
#else
  virtual int poll(pollfd *fds, nfds_t nfds, int timeout) const noexcept;
#endif

  // If strtonum() is available, wrapper that can be mocked in tests, else
  // implementation of strtonum() borrowed from OpenBSD.
  virtual long long Strtonum(
      const char *s, long long minval, long long maxval,
      const char **err) const noexcept;

#ifdef _WIN32
  // ioctlsocket() wrapper that can be mocked in tests.
  virtual int ioctlsocket(Socket s, long cmd, u_long *argp) const noexcept;
#else
  // Wrapper for fcntl() taking just two arguments. Good for getting the
  // currently value of the socket flags.
  virtual int fcntl(Socket s, int cmd) const noexcept;

  // Wrapper for fcntl() taking three arguments with the third argument
  // being an integer value. Good for setting O_NONBLOCK on a socket.
  virtual int fcntl(Socket s, int cmd, int arg) const noexcept;
#endif

  // getsockopt() wrapper that can be mocked in tests.
  virtual int getsockopt(
      Socket socket, int level, int name, void *value,
      socklen_t *len) const noexcept;

  // ~Sys is the destructor
  virtual ~Sys() noexcept;
};

// LIBNDT_NO_INLINE_IMPL controls whether to inline the impl
#ifndef LIBNDT_NO_INLINE_IMPL

// LIBNDT_HAVE_STRTONUM tells us whether we have strtonum in libc
#ifndef LIBNDT_HAVE_STRTONUM
// clang-format off
/*
 * Copyright (c) 2004 Ted Unangst and Todd Miller
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define	INVALID		1
#define	TOOSMALL	2
#define	TOOLARGE	3

static long long
strtonum(const char *numstr, long long minval, long long maxval,
    const char **errstrp)
{
	long long ll = 0;
	int error = 0;
	char *ep;
	struct errval {
		const char *errstr;
		int err;
	} ev[4] = {
		{ NULL,		0 },
		{ "invalid",	EINVAL },
		{ "too small",	ERANGE },
		{ "too large",	ERANGE },
	};

	ev[0].err = errno;
	errno = 0;
	if (minval > maxval) {
		error = INVALID;
	} else {
		ll = strtoll(numstr, &ep, 10);
		if (numstr == ep || *ep != '\0')
			error = INVALID;
		else if ((ll == LLONG_MIN && errno == ERANGE) || ll < minval)
			error = TOOSMALL;
		else if ((ll == LLONG_MAX && errno == ERANGE) || ll > maxval)
			error = TOOLARGE;
	}
	if (errstrp != NULL)
		*errstrp = ev[error].errstr;
	errno = ev[error].err;
	if (error)
		ll = 0;

	return (ll);
}
// clang-format on
#endif  // LIBNDT_HAVE_STRTONUM

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

int Sys::get_last_error() const noexcept {
#ifdef _WIN32
  return GetLastError();
#else
  return errno;
#endif
}

void Sys::set_last_error(int err) const noexcept {
#ifdef _WIN32
  SetLastError(err);
#else
  errno = err;
#endif
}

int Sys::getaddrinfo(const char *domain, const char *port,
                     const addrinfo *hints, addrinfo **res) const noexcept {
  return ::getaddrinfo(domain, port, hints, res);
}

int Sys::getnameinfo(const sockaddr *sa, socklen_t salen, char *host,
                     socklen_t hostlen, char *serv, socklen_t servlen,
                     int flags) const noexcept {
  return ::getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
}

void Sys::freeaddrinfo(addrinfo *aip) const noexcept { ::freeaddrinfo(aip); }

Socket Sys::socket(int domain, int type, int protocol) const noexcept {
  return (Socket)::socket(domain, type, protocol);
}

int Sys::connect(Socket fd, const sockaddr *sa, socklen_t len) const noexcept {
  return ::connect(fd, sa, len);
}

Ssize Sys::recv(Socket fd, void *base, Size count) const noexcept {
  if (count > LIBNDT_OS_SSIZE_MAX) {
    set_last_error(LIBNDT_OS_EINVAL);
    return -1;
  }
  int flags = 0;
#ifdef LIBNDT_HAVE_MSG_NOSIGNAL
  // On Linux systems this flag prevents socket ops from raising SIGPIPE.
  flags |= MSG_NOSIGNAL;
#endif
  return (Ssize)::recv(
      fd, LIBNDT_AS_OS_BUFFER(base), LIBNDT_AS_OS_BUFFER_LEN(count), flags);
}

Ssize Sys::send(Socket fd, const void *base, Size count) const noexcept {
  if (count > LIBNDT_OS_SSIZE_MAX) {
    set_last_error(LIBNDT_OS_EINVAL);
    return -1;
  }
  int flags = 0;
#ifdef LIBNDT_HAVE_MSG_NOSIGNAL
  // On Linux systems this flag prevents socket ops from raising SIGPIPE.
  flags |= MSG_NOSIGNAL;
#endif
  return (Ssize)::send(
      fd, LIBNDT_AS_OS_BUFFER(base), LIBNDT_AS_OS_BUFFER_LEN(count), flags);
}

int Sys::shutdown(Socket fd, int shutdown_how) const noexcept {
  return ::shutdown(fd, shutdown_how);
}

int Sys::closesocket(Socket fd) const noexcept {
#ifdef _WIN32
  return ::closesocket(fd);
#else
  return ::close(fd);
#endif
}

#ifdef _WIN32
int Sys::poll(LPWSAPOLLFD fds, ULONG nfds, INT timeout) const noexcept {
  return ::WSAPoll(fds, nfds, timeout);
}
#else
int Sys::poll(pollfd *fds, nfds_t nfds, int timeout) const noexcept {
  return ::poll(fds, nfds, timeout);
}
#endif

long long Sys::Strtonum(const char *s, long long minval,
                        long long maxval, const char **errp) const noexcept {
  return strtonum(s, minval, maxval, errp);
}

#ifdef _WIN32
int Sys::ioctlsocket(Socket s, long cmd, u_long *argp) const noexcept {
  return ::ioctlsocket(s, cmd, argp);
}
#else
int Sys::fcntl(Socket s, int cmd) const noexcept { return ::fcntl(s, cmd); }
int Sys::fcntl(Socket s, int cmd, int arg) const noexcept {
  return ::fcntl(s, cmd, arg);
}
#endif

int Sys::getsockopt(Socket socket, int level, int name, void *value,
                    socklen_t *len) const noexcept {
  return ::getsockopt(
      socket, level, name, LIBNDT_AS_OS_OPTION_VALUE(value), len);
}

Sys::~Sys() noexcept {}

#endif  // LIBNDT_NO_INLINE_IMPL
}  // namespace libndt
}  // namespace measurement_kit
#endif  // MEASUREMENT_KIT_LIBNDT_SYS_HPP
