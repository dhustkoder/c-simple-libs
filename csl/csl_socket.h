#ifndef CSL_SOCKET_H_
#define CSL_SOCKET_H_


#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET Socket;

#define CSL_WSA_VERSION_MAJOR (2)
#define CSL_WSA_VERSION_MINOR (2)
#define CSL_INVALID_SOCKET    (INVALID_SOCKET)
#define CSL_SOCKET_ERROR      (SOCKET_ERROR)

#elif defined(__linux__)
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>


typedef int Socket;

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


enum protocol {
	CSL_PROTOCOL_UDP,
	CSL_PROTOCOL_TCP,
	CSL_PROTOCOL_COUNT
};
typedef int Protocol;


CSLDEF int csl_socket_init(void);
CSLDEF void csl_socket_term(void);
CSLDEF Socket csl_socket_open(Protocol proto);
CSLDEF int csl_socket_connect(Socket s, const char* ip, short port);
CSLDEF int csl_socket_bind(Socket s, short port);
CSLDEF int csl_socket_listen(Socket s, int backlog);
CSLDEF Socket csl_socket_accept(Socket listener);
CSLDEF int csl_socket_send(Socket s, const void* data, int len);
CSLDEF int csl_socket_recv(Socket s, void* data, int len);
CSLDEF void csl_socket_close(Socket s);



#if defined(CSL_SOCKET_IMPLEMENTATION)
#include <string.h>

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

CSLDEF int csl_socket_send(Socket s, const void* data, int len)
{
	const char* p = data;
	while (len > 0) {
		int packet_size = len > CSL_SOCKET_MAX_PACKET_SIZE 
		                  ? CSL_SOCKET_MAX_PACKET_SIZE
				  : len;
		int ret = send(s, p, packet_size, 0); 

		if (ret == CSL_SOCKET_ERROR)
			return 1;

		len -= ret;
		p += ret;
	}
	return 0;
}

CSLDEF int csl_socket_recv(Socket s, void* data, int len)
{
	char* p = data;
	while (len > 0) {
		int packet_size = len > CSL_SOCKET_MAX_PACKET_SIZE 
		                  ? CSL_SOCKET_MAX_PACKET_SIZE
				  : len;
		int ret = recv(s, p, packet_size, 0); 

		if (ret == CSL_SOCKET_ERROR)
			return 1;

		len -= ret;
		p += ret;
	}
	return 0;
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

