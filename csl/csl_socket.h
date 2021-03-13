#ifndef CSL_SOCKET_H_
#define CSL_SOCKET_H_


#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET Socket;
typedef int(*Socket_IO_FNP)();

#define CSL_WSA_VERSION_MAJOR (2)
#define CSL_WSA_VERSION_MINOR (2)
#define CSL_INVALID_SOCKET    (INVALID_SOCKET)
#define CSL_SOCKET_ERROR      (SOCKET_ERROR)

#elif defined(__linux__)
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>


typedef int Socket;
typedef ssize_t(*Socket_IO_FNP)();

#define CSL_INVALID_SOCKET (-1)
#define CSL_SOCKET_ERROR   (-1)


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


enum csl_protocol {
	CSL_PROTOCOL_UDP,
	CSL_PROTOCOL_TCP,
	CSL_PROTOCOL_COUNT
};
typedef int Protocol;

enum csl_io_opt {
	CSL_IO_OPT_WAIT,
	CSL_IO_OPT_DONTWAIT,
	CSL_IO_OPT_COUNT,
};
typedef int IO_OPT;

CSLDEF int csl_socket_init(void);
CSLDEF void csl_socket_term(void);
CSLDEF Socket csl_socket_open(Protocol proto);
CSLDEF int csl_socket_connect(Socket s, const char* ip, short port);
CSLDEF int csl_socket_bind(Socket s, short port);
CSLDEF int csl_socket_listen(Socket s, int backlog);
CSLDEF Socket csl_socket_accept(Socket listener);
CSLDEF int csl_socket_send(Socket s, const void* data, int len, IO_OPT opt);
CSLDEF int csl_socket_recv(Socket s, void* data, int len, IO_OPT opt);
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

static int csl_fionbio(Socket s, int nblock)
{
	int ret;
#if defined(__linux__)
	int param = nblock ? 1 : 0;
	ret = ioctl(s, FIONBIO, &param);
#elif defined(_WIN32)
	u_long param = nblock ? 1 : 0;
	ret = ioctlsocket(s, FIONBIO, &param);
#endif
	return ret;
}

static int csl_io_wrap(Socket s, const void* data, int len, IO_OPT opt, Socket_IO_FNP iofn)
{
	const int err = csl_fionbio(s, opt == CSL_IO_OPT_DONTWAIT ? 1 : 0);	
	if (err == CSL_SOCKET_ERROR)
		return err;

	const char* p = data;
	int track_bytes = 0;

	while (len > 0) {
		int packet_size = len > CSL_SOCKET_MAX_PACKET_SIZE 
		                  ? CSL_SOCKET_MAX_PACKET_SIZE
				  : len;
		const int nbytes = iofn(s, (void*)p, packet_size, 0); 

		if (nbytes == CSL_SOCKET_ERROR) {
#if defined(_WIN32)
			if (WSAGetLastError() == WSAEWOULDBLOCK)
				return track_bytes;
			else
				return nbytes;
#elif defined(__linux__)
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return track_bytes;
			else
				return nbytes;
#endif
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

CSLDEF Socket csl_socket_open(Protocol proto)
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

CSLDEF int csl_socket_send(Socket s, const void* data, int len, IO_OPT opt)
{
	return csl_io_wrap(s, data, len, opt, send);
}

CSLDEF int csl_socket_recv(Socket s, void* data, int len, IO_OPT opt)
{
	return csl_io_wrap(s, data, len, opt, recv);
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

