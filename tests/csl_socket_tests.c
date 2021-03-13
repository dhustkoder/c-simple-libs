
#include <assert.h>
#include <stdio.h>

#define CSL_STATIC
#define CSL_SOCKET_IMPLEMENTATION
#include "csl_socket.h"



void udp_test(void)
{
	Socket out = csl_socket_open(CSL_PROTOCOL_UDP);
	Socket in  = csl_socket_open(CSL_PROTOCOL_UDP);	

	assert(out != CSL_INVALID_SOCKET && in != CSL_INVALID_SOCKET);
	
	int ret;
	ret = csl_socket_bind(in, 7171);	
	assert(ret == 0);
	ret = csl_socket_connect(out, "127.0.0.1", 7171);
	assert(ret == 0);

	const char match[] = "0xdeadcode";
	char data[sizeof(match) + 1] = { 0 };
	ret = csl_socket_recv(in, data, sizeof(match), CSL_IO_OPT_DONTWAIT);
	assert(ret == 0);
	ret = csl_socket_send(out, match, sizeof(match), CSL_IO_OPT_WAIT);
	assert(ret == sizeof(match));
	ret = csl_socket_recv(in, data, sizeof(match), CSL_IO_OPT_WAIT); 
	assert(ret == sizeof(match));

	ret = memcmp(match, data, sizeof(match));

	assert(ret == 0);
	printf("%s\n", data);
	csl_socket_close(out);
	csl_socket_close(in);
}

void tcp_test(void)
{
	Socket client = csl_socket_open(CSL_PROTOCOL_TCP);
	Socket server = csl_socket_open(CSL_PROTOCOL_TCP);
	assert(client != CSL_INVALID_SOCKET && server != CSL_INVALID_SOCKET);
	
	int ret;
	ret = csl_socket_bind(server, 7171);
	assert(ret == 0);
	ret = csl_socket_listen(server, 1);
	assert(ret == 0);
	ret = csl_socket_connect(client, "127.0.0.1", 7171);
	assert(ret == 0);
	Socket client_ret = csl_socket_accept(server);
	assert(client_ret != CSL_INVALID_SOCKET);

	const char match[] = "0xdeadcode";
	char data[sizeof(match) + 1] = { 0 };
	ret = csl_socket_recv(client_ret, data, sizeof(match), CSL_IO_OPT_DONTWAIT);
	assert(ret == 0);
	ret = csl_socket_send(client, match, sizeof(match), CSL_IO_OPT_WAIT);
	assert(ret == sizeof(match));
	ret = csl_socket_recv(client_ret, data, sizeof(match), CSL_IO_OPT_WAIT); 
	assert(ret == sizeof(match));

	ret = memcmp(match, data, sizeof(match));

	assert(ret == 0);
	printf("%s\n", data);
	csl_socket_close(client);
	csl_socket_close(server);
}

int main(void)
{
	int ret = csl_socket_init();
	assert(ret == 0);
	udp_test();
	tcp_test();
	csl_socket_term();
}





