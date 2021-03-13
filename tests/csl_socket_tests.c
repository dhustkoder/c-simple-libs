
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#define CSL_STATIC
#define CSL_SOCKET_IMPLEMENTATION
#include "csl_socket.h"


void data_transfer_test(Socket a, Socket b, int size)
{
	int ret;

	char* sendbuf = malloc(size);
	char* recvbuf = malloc(size);

	memset(sendbuf, 0xFF, size);
	memset(recvbuf, 0x00, size);
 

	/* test wait */
	ret = csl_socket_send(b, sendbuf, size, CSL_IO_OPT_WAIT);
	assert(ret == size);

	ret = csl_socket_recv(a, recvbuf, size, CSL_IO_OPT_WAIT); 
	assert(ret == size);

	ret = memcmp(recvbuf, sendbuf, size);
	assert(ret == 0);


	printf("data transfer test (WAIT) size: %d... PASSED\n", size);

	free(recvbuf);
	free(sendbuf);
}



void udp_test(void)
{
	Socket a  = csl_socket_open(CSL_PROTOCOL_UDP);
	Socket b  = csl_socket_open(CSL_PROTOCOL_UDP);	

	assert(a != CSL_INVALID_SOCKET && b != CSL_INVALID_SOCKET);
	
	int ret;

	ret = csl_socket_bind(a, 7171);	
	assert(ret == 0);

	ret = csl_socket_connect_hostname(b, "localhost", 7171);
	assert(ret == 0);

	const int sizes[] = { 128, 512, 1024, 2048, 4096, 8192 };
	for (size_t i = 0; i < (sizeof(sizes)/sizeof(sizes[0])); ++i)
		data_transfer_test(a, b, sizes[i]);

	csl_socket_close(a);
	csl_socket_close(b);


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

	const int sizes[] = { 128, 512, 1024, 2048, 4096, 8192 };
	for (size_t i = 0; i < (sizeof(sizes)/sizeof(sizes[0])); ++i)
		data_transfer_test(client_ret, client, sizes[i]);


	csl_socket_close(client);
	csl_socket_close(client_ret);
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





