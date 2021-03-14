#ifndef CSL_SOCKET_H_
#define CSL_SOCKET_H_


#if defined(_WIN32)

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdbool.h>

typedef SOCKET Socket;
typedef int Socket_IO_Len;
typedef Socket_IO_Len(*Socket_IO_FNP)();

#define CSL_WSA_VERSION_MAJOR (2)
#define CSL_WSA_VERSION_MINOR (2)
#define CSL_INVALID_SOCKET    (INVALID_SOCKET)
#define CSL_SOCKET_ERROR      (SOCKET_ERROR)
#define CSL_EWOULDBLOCK       (WSAEWOULDBLOCK)
#define CSL_EAGAIN            (0)

#elif defined(__linux__)
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>


typedef int Socket;
typedef ssize_t Socket_IO_Len;
typedef Socket_IO_Len(*Socket_IO_FNP)();

#define CSL_INVALID_SOCKET (-1)
#define CSL_SOCKET_ERROR   (-1)
#define CSL_EAGAIN         (EAGAIN)
#define CSL_EWOULDBLOCK    (EWOULDBLOCK)

#else
#error "Undefined Platform"
#endif

#ifndef CSLDEF
#ifdef CSL_STATIC
#define CSLDEF static
#else
#define CSLDEF extern
#endif
#endif


#define CSL_SOCKET_MAX_PACKET_SIZE 1024


typedef enum csl_protocol {
	CSL_PROTOCOL_UDP,
	CSL_PROTOCOL_TCP,
	CSL_PROTOCOL_COUNT
} CSL_Proto;

CSLDEF int csl_socket_init(void);
CSLDEF void csl_socket_term(void);
CSLDEF Socket csl_socket_open(CSL_Proto proto);
CSLDEF int csl_socket_connect(Socket s, const char* ip, short port);
CSLDEF int csl_socket_connect_hostname(Socket s, const char* hostname, short port);
CSLDEF int csl_socket_bind(Socket s, short port);
CSLDEF int csl_socket_listen(Socket s, int backlog);
CSLDEF Socket csl_socket_accept(Socket listener);
CSLDEF int csl_socket_send(Socket s, const void* data, int len, bool blocking);
CSLDEF int csl_socket_recv(Socket s, void* data, int len, bool blocking);
CSLDEF int csl_socket_last_error(void);
CSLDEF const char* csl_socket_last_error_str(void);
CSLDEF void csl_socket_close(Socket s);



#if defined(CSL_SOCKET_IMPLEMENTATION)
#include <string.h>
#include <limits.h>
#include <errno.h>

static void csl_sockaddr_setup(struct sockaddr_in* addr, const char* ip, short port)
{
	memset(addr, 0, sizeof(*addr));
	addr->sin_family = AF_INET;
	addr->sin_port = htons(port);
	if (ip != NULL) {
#if defined(_WIN32)
		InetPton(AF_INET, ip, &addr->sin_addr);
#else
		inet_pton(AF_INET, ip, &addr->sin_addr);
#endif
	} else {
		addr->sin_addr.s_addr = INADDR_ANY;
	}
}
/*
static int csl_fionread(Socket s)
{
	int ret;

#if defined(__linux__)
	int nread;
	ret = ioctl(s, FIONREAD, &nread);
#elif defined(_WIN32)
	u_long nread;
	ret = ioctlsocket(s, cmd, &nread);
	nread = nread <= INT_MAX ? nread : INT_MAX;
#endif
	return (ret == CSL_SOCKET_ERROR) ? ret : nread;
}*/

static int csl_fionbio(Socket s, bool blocking)
{
	int ret;
#if defined(__linux__)
	int param = blocking ? 1 : 0;
	ret = ioctl(s, FIONBIO, &param);
#elif defined(_WIN32)
	u_long param = blocking ? 1 : 0;
	ret = ioctlsocket(s, FIONBIO, &param);
#endif
	return ret;
}

static int csl_io_wrap(Socket s, const void* data, int len, bool blocking, Socket_IO_FNP iofn)
{
	const int err = csl_fionbio(s, blocking);	
	if (err == CSL_SOCKET_ERROR)
		return err;

	const char* p = data;
	int track_bytes = 0;

	while (len > 0) {
		int packet_size = len > CSL_SOCKET_MAX_PACKET_SIZE 
		                  ? CSL_SOCKET_MAX_PACKET_SIZE
				  : len;
		const Socket_IO_Len nbytes = iofn(s, (void*)p, packet_size, 0); 

		if (nbytes == CSL_SOCKET_ERROR) {
			const int errcode = csl_socket_last_error();
			if (errcode == CSL_EWOULDBLOCK ||
			    errcode == CSL_EAGAIN) {
				return track_bytes;
			} else {
				return nbytes;
			}
		}


		len -= nbytes;
		p += nbytes;
		track_bytes += nbytes;
	}

	return track_bytes;
}


CSLDEF int csl_socket_init(void)
{
#if defined(_WIN32)
	WSADATA wsa;
	const int major = CSL_WSA_VERSION_MAJOR;
	const int minor = CSL_WSA_VERSION_MINOR;
	if (WSAStartup(MAKEWORD(major, minor), &wsa) != 0) 
		return 1; 
#endif

	return 0;
}

CSLDEF void csl_socket_term(void)
{
#if defined(_WIN32)
	WSACleanup();
#endif
}

CSLDEF Socket csl_socket_open(CSL_Proto proto)
{
	const int protonum = proto == CSL_PROTOCOL_UDP ? IPPROTO_UDP : IPPROTO_TCP;
	const int socktype = proto == CSL_PROTOCOL_UDP ? SOCK_DGRAM  : SOCK_STREAM;
	return socket(AF_INET, socktype, protonum);
}

CSLDEF int csl_socket_connect(Socket s, const char* ip, short port)
{
	struct sockaddr_in addr;
	csl_sockaddr_setup(&addr, ip, port);
	return connect(s, (struct sockaddr*)&addr, sizeof(addr));
}

CSLDEF int csl_socket_connect_hostname(Socket s, const char* hostname, short port)
{
	struct hostent* he;
	const char* ip;
	
	he = gethostbyname(hostname);
	if (he == NULL) 
		return 1;
	
	ip = inet_ntoa(*(struct in_addr*)*he->h_addr_list);

	return csl_socket_connect(s, ip, port);
	
}

CSLDEF int csl_socket_bind(Socket s, short port)
{
	struct sockaddr_in addr;
	csl_sockaddr_setup(&addr, NULL, port);
	return bind(s, (struct sockaddr*)&addr, sizeof(addr));
}

CSLDEF int csl_socket_listen(Socket s, int backlog)
{
	return listen(s, backlog);
}

CSLDEF Socket csl_socket_accept(Socket listener)
{
	return accept(listener, NULL, NULL);
}

CSLDEF int csl_socket_send(Socket s, const void* data, int len, bool blocking)
{
	return csl_io_wrap(s, data, len, blocking, send);
}

CSLDEF int csl_socket_recv(Socket s, void* data, int len, bool blocking)
{
	return csl_io_wrap(s, data, len, blocking, recv);
}

CSLDEF int csl_socket_last_error(void) 
{
#if defined(_WIN32)
	return WSAGetLastError();
#elif defined(__linux__)
	return errno ? errno : h_errno;
#endif
}

CSLDEF const char* csl_socket_last_error_str(void)
{
#if defined(_WIN32)
	static char buffer[64];
	DWORD lasterr = WSAGetLastError();
	LPSTR str = NULL;

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		lasterr,
		0,
		&str,
		0,
		NULL
	);

	if (str != NULL) {
		size_t len = strlen(str);
		if (len >= sizeof(buffer))
			len = sizeof(buffer) - 1;
		memcpy(buffer, str, len);
		buffer[len] = '\0';
		LocalFree(str);
		return buffer;
	}

	return NULL;

#elif defined(__linux__)
	return errno ? strerror(errno) : hstrerror(h_errno);
#endif
}

CSLDEF void csl_socket_close(Socket s)
{
#if defined(_WIN32)
	closesocket(s);
#else
	close(s);
#endif
}











#endif /* CSL_SOCKET_IMPLEMENTATION */
#endif /* CSL_SOCKET_H_ */

