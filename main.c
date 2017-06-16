#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/types.h>
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
	(void)size2;//BREAKPOINT
	socks105_request_delete(req2);
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
	(void)size2;//BREAKPOINT
	socks105_initial_reply_delete(irep2);
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
	(void)size2;//BREAKPOINT
	socks105_final_reply_delete(frep2);
}

#define REQ "GET / HTTP/1.1\r\n\r\n"

void test_case_wget_google()
{
	struct socks105_request req = {
		.auth_info = { 0, NULL },
		.req_type = SOCKS105_REQ_TCP_CONNECT,
		.tfo = 1,
		.server_info = {
			.addr_type = SOCKS105_ADDR_DOMAIN,
			.addr.domain = "google.ro",
			.port = 80,
		},
		.initial_data_size = strlen(REQ),
		.initial_data = REQ,
	};
	
	char buf[1500];
	
	ssize_t req_size = socks105_request_pack(&req, buf, 1500);
	if (req_size < 0)
		return;
	
	int sock;
	
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0)
	{
		perror("socket");
		goto done;
	}
	
	struct sockaddr_in localhost = {
		.sin_family = AF_INET,
		.sin_port = htons(1080),
		.sin_addr = { .s_addr = inet_addr("127.0.0.1") },
	};
	
	int err = sendto(sock, (const void *)buf, req_size, MSG_FASTOPEN, (const struct sockaddr *) &localhost, sizeof(struct sockaddr_in));
	if (err < 0)
	{
		perror("sendto");
		goto done;
	}
	
	memset(buf, 0, sizeof(buf));
	
	enum
	{
		RECV_IREP,
		RECV_FREP,
		RECV_DATA,
	};
	
	int stage = RECV_IREP;
	int offset = 0;
	
	while (1)
	{
		ssize_t bytes = recv(sock, buf + offset, sizeof(buf) - offset, 0);
		if (bytes == 0)
		{
			fprintf(stderr, "connection closed\n");
			goto done;
		}
		if (bytes < 0)
		{
			perror("recv");
			goto done;
		}
		
		if (stage == RECV_IREP)
		{
			struct socks105_initial_reply *irep;
			ssize_t size2 = socks105_initial_reply_parse(buf + offset, sizeof(buf) - offset, &irep);
			if (size2 < 0)
			{
				fprintf(stderr, "fuck\n");
				goto done;
			}
			socks105_initial_reply_delete(irep);
			fprintf(stderr, "got irep\n");
			stage = RECV_FREP;
		}
		else if (stage == RECV_FREP)
		{
			struct socks105_final_reply *frep;
			ssize_t size2 = socks105_final_reply_parse(buf + offset, sizeof(buf) - offset, &frep);
			if (size2 < 0)
			{
				fprintf(stderr, "fuck\n");
				goto done;
			}
			socks105_final_reply_delete(frep);
			fprintf(stderr, "got frep\n");
			stage = RECV_DATA;
		}
		else if (stage == RECV_DATA)
		{
			printf("%s\n", buf + offset);
			goto done;
		}
		
		offset += bytes;
	}
	
done:
	close(sock);
}

int main(int argc, char *argv[])
{
	(void)argc; (void)argv;
//	test_case_basic_request();
//	test_case_basic_initial_reply();
//	test_case_basic_final_reply();
	test_case_wget_google();
	
	return 0;
}
