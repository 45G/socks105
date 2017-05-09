#ifndef SOCKS105_H
#define SOCKS105_H

/*
 * Experimental SCOKS105 implementation
 * 
 * Will crash as soon as something goes wrong
 */

#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

enum socks105_error
{
	SOCKS105_ERROR_SUCCESS     = 0,
	SOCKS105_ERROR_INVALID     = -1,   /* some invalid field*/
	SOCKS105_ERROR_ALLOC       = -2,   /* malloc fail */
	SOCKS105_ERROR_BUFFER      = -3,   /* reached end of buffer */
	SOCKS105_ERROR_UNSUPPORTED = -100, /* unsupported/unimplemented stuff */
};

enum socks105_req_type
{
	SOCKS105_REQ_TCP_CONNECT = 0x01,
	SOCKS105_REQ_TCP_LISTEN  = 0x02,
	SOCKS105_REQ_UDP         = 0x03,
	SOCKS105_REQ_INVALID     = 0xff,
};

enum socks105_addr_type
{
	SOCKS105_ADDR_IPV4    = 0x01,
	SOCKS105_ADDR_DOMAIN  = 0x03,
	SOCKS105_ADDR_IPV6    = 0x04,
	SOCKS105_ADDR_INVALID = 0xff,
};

enum socks105_initial_reply_type
{
	SOCKS105_INITIAL_REPLY_SUCCESS = 0x00,
	SOCKS105_INITIAL_REPLY_FAILURE = 0x01,
};

enum socks105_final_reply_type
{
	SOCKS105_FINAL_REPLY_SUCCESS            = 0x00,
	SOCKS105_FINAL_REPLY_FAILURE            = 0x01, /* general SOCKS server failure */
	SOCKS105_FINAL_REPLY_NOT_ALLOWED        = 0x02, /* connection not allowed by ruleset */
	SOCKS105_FINAL_REPLY_NET_UNREACH        = 0x03, /* network unreachable */
	SOCKS105_FINAL_REPLY_HOST_UNREACH       = 0x04, /* host unreachable */
	SOCKS105_FINAL_REPLY_REFUSED            = 0x05, /* connection refused */
	SOCKS105_FINAL_REPLY_TTL_EXPIRED        = 0x06, /* TTL expired */
	SOCKS105_FINAL_REPLY_CMD_NOT_SUPPORTED  = 0x07, /* command not supported */
	SOCKS105_FINAL_REPLY_ADDR_NOT_SUPPORTED = 0x08, /* address type not supported */
};

struct socks105_auth_data
{
	uint8_t method;
	void *data;
	uint8_t data_len;
};

struct socks105_auth_info
{
	size_t count;
	struct socks105_auth_data *auth_data;
};

struct socks105_server_info
{
	enum socks105_addr_type addr_type;
	union
	{
		uint32_t ipv4;
		char *domain;
		uint8_t ipv6[16];
	} addr;
	uint16_t port;
};

struct socks105_request
{
	struct socks105_auth_info auth_info;
	enum socks105_req_type req_type;
	int tfo;
	struct socks105_server_info server_info;
	uint16_t initial_data_size;
	void *initial_data;
};

struct socks105_initial_reply
{
	enum socks105_initial_reply_type type;
	uint8_t method;
	struct socks105_auth_info auth_info;
};

struct socks105_final_reply
{
	enum socks105_final_reply_type type;
	struct socks105_server_info server_info;
	size_t data_offset;
};

//struct socks105_request *socks105_request_create();
ssize_t socks105_request_parse(void *buf, size_t buf_len, struct socks105_request **req);
void socks105_request_delete(struct socks105_request *req);
ssize_t socks105_request_pack(struct socks105_request *req, void *buf, size_t buf_len);

//void socks105_request_add_method(uint8_t method, void *data, size_t len);
//void socks105_request_set_type(enum socks105_req_type type);
//void socks105_request_set_tfo(int tfo);
//void socks105_request_set_addr_ipv4(uint32_t ipv4);
//void socks105_request_set_addr_domain(char *domain);
//void socks105_request_set_addr_ipv6(uint8_t ipv6[16]);
//void socks105_request_set_port(uint16_t port);
//void socks105_request_set_data(void *buf, size_t len);


//struct socks105_initial_reply *socks105_initial_reply_create();
int socks105_initial_reply_parse(void *buf, size_t buf_len, struct socks105_initial_reply **ret);
void socks105_initial_reply_delete(struct socks105_initial_reply *irep);
ssize_t socks105_initial_reply_pack(struct socks105_initial_reply *irep, void *buf, size_t buf_len);

//void socks105_initial_reply_set_type(enum socks105_initial_reply_type type);
//void socks105_initial_reply_set_method(struct socks105_initial_reply *irep, uint8_t method);
//void socks105_initial_reply_add_method(uint8_t method, void *data, size_t len);


//struct socks105_final_reply *socks105_final_reply_create();
int socks105_final_reply_parse(void *buf, size_t buf_len, struct socks105_final_reply **ret);
void socks105_final_reply_delete(struct socks105_final_reply *frep);
ssize_t socks105_final_reply_pack(struct socks105_final_reply *frep, void *buf, size_t buf_len);

//void socks105_final_reply_set_type(enum socks105_final_reply_type type);
//void socks105_request_set_addr_ipv4(uint32_t ipv4);
//void socks105_request_set_addr_domain(char *domain);
//void socks105_request_set_addr_ipv6(uint8_t ipv6[16]);
//void socks105_request_set_port(uint16_t port);
//void socks105_final_reply_set_data_offset(struct socks105_final_reply *frep, size_t data_offset);

#endif // SOCKS105_H
