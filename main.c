#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include "socks105.h"

#define INITIAL_DATA "gugu gaga mama caca"

void test_case_basic_request()
{
	struct socks105_request req = {
		.auth_info = { 0, NULL },
		.req_type = SOCKS105_REQ_TCP_CONNECT,
		.tfo = 1,
		.server_info = {
			.addr_type = SOCKS105_ADDR_IPV4,
			.addr.ipv4 = inet_addr("8.8.8.8"),
			.port = 80,
		},
		.initial_data_size = strlen(INITIAL_DATA),
		.initial_data = INITIAL_DATA,
	};
	
	char buf[1500];
	
	ssize_t size = socks105_request_pack(&req, buf, 1500);
	if (size < 0)
		return;
	
	struct socks105_request *req2;
	ssize_t size2 = socks105_request_parse(buf, 1500, &req2);
	
}

void test_case_basic_initial_reply()
{
	struct socks105_initial_reply irep = {
		.irep_type = SOCKS105_INITIAL_REPLY_SUCCESS,
		.method = 0,
		.auth_info = { 0, NULL },
	};
	
	char buf[1500];
	
	ssize_t size = socks105_initial_reply_pack(&irep, buf, 1500);
	if (size < 0)
		return;
	
	struct socks105_initial_reply *irep2;
	ssize_t size2 = socks105_initial_reply_parse(buf, 1500, &irep2);
	
}

void test_case_basic_final_reply()
{
	struct socks105_final_reply frep = {
		.frep_type = SOCKS105_FINAL_REPLY_SUCCESS,
		.server_info = {
			.addr_type = SOCKS105_ADDR_IPV4,
			.addr.ipv4 = inet_addr("8.8.8.8"),
			.port = 80,
		},
		.data_offset = strlen(INITIAL_DATA),
	};
	
	char buf[1500];
	
	ssize_t size = socks105_final_reply_pack(&frep, buf, 1500);
	if (size < 0)
		return;
	
	struct socks105_final_reply *frep2;
	ssize_t size2 = socks105_final_reply_parse(buf, 1500, &frep2);
	
}

int main(int argc, char *argv[])
{
	(void)argc; (void)argv;
	test_case_basic_request();
	test_case_basic_initial_reply();
	test_case_basic_final_reply();
	return 0;
}
