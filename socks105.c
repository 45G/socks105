#include <string.h>
#include <strings.h>
#include <arpa/inet.h>
#include "socks105.h"

#define CHECK(how, err, jump) \
{ \
	(err) = (how); \
	if ((err) < 0) \
		goto jump; \
}

struct bufstream
{
	uint8_t *buf;
	size_t len;
};

void *bufstream_take(struct bufstream *bs, size_t len)
{
	void *ret = bs->buf;
	
	if (len > bs->len)
		return NULL;
	
	bs->buf += len;
	bs->len -= len;
	
	return ret;
}

static int byte_parse(struct bufstream *bs, uint8_t *byte)
{
	uint8_t *data = bufstream_take(bs, sizeof(uint8_t));
	if (!data)
		return -SOCKS105_ERROR_BUFFER;
	
	*byte = *data;
	
	return 0;
}

static int byte_pack(struct bufstream *bs, uint8_t byte)
{
	if (bs->len < sizeof(uint8_t))
		return -SOCKS105_ERROR_BUFFER;
	
	bs->buf[0] = byte;
	bs->buf += sizeof(uint8_t);
	bs->len -= sizeof(uint8_t);
	
	return 0;
}

static int byte_to_int_parse(struct bufstream *bs, int *num)
{
	uint8_t byte;
	int err;
	
	CHECK(byte_parse(bs, &byte), err, fail);
	*num = byte;
	
fail:
	return err;
}

static int ipv4_parse(struct bufstream *bs, uint32_t *ip)
{
	uint32_t *data = bufstream_take(bs, sizeof(uint32_t));
	if (!data)
		return -SOCKS105_ERROR_BUFFER;
	
	*ip = *data;
	
	return 0;
}

static int ipv4_pack(struct bufstream *bs, uint32_t ip)
{
	if (bs->len < sizeof(uint32_t))
		return -SOCKS105_ERROR_BUFFER;
	
	uint32_t *buf = (uint32_t *)bs->buf;
	*buf = ip;
	bs->buf += sizeof(uint32_t);
	bs->len -= sizeof(uint32_t);
	
	return 0;
}

static int ipv6_parse(struct bufstream *bs, uint8_t *ipv6)
{
	uint8_t *data = bufstream_take(bs, 16);
	if (!data)
		return -SOCKS105_ERROR_BUFFER;
	
	memcpy(ipv6, data, 16);
	
	return 0;
}

static int blob_pack(struct bufstream *bs, size_t len, uint8_t *blob)
{
	if (bs->len < len)
		return -SOCKS105_ERROR_BUFFER;
	
	memcpy(bs->buf, blob, len);
	bs->buf += len;
	bs->len -= len;
	
	return 0;
}

static int ipv6_pack(struct bufstream *bs, uint8_t *ipv6)
{
	return blob_pack(bs, 16, ipv6);
}

//static int string_pack(struct bufstream *bs, char *str)
//{
//	return blob_pack(bs, strlen(str), (uint8_t *)str);
//}

static int blob_parse(struct bufstream *bs, size_t len, void **str, int as_string)
{
	uint8_t *data = bufstream_take(bs, len);
	if (!data)
		return -SOCKS105_ERROR_BUFFER;
	
	if (as_string)
	{
		for (int i = 0; i < (int)len; i++)
		{
			if (data[i] == 0)
				return -SOCKS105_ERROR_INVALID;
		}
	}
			
	*str = malloc(len + (as_string ? 1 : 0));
	if (!*str)
		return -SOCKS105_ERROR_ALLOC;
	if (as_string)
		((char *)*str)[len] = 0;
	memcpy(*str, data, len);
	
	return 0;
}

static int short_parse(struct bufstream *bs, uint16_t *num)
{
	uint16_t *data = bufstream_take(bs, sizeof(uint16_t));
	if (!data)
		return -SOCKS105_ERROR_BUFFER;
	
	*num = ntohs(*data);
	
	return 0;
}

static int short_pack(struct bufstream *bs, uint16_t num)
{
	uint16_t *data = bufstream_take(bs, sizeof(uint16_t));
	if (!data)
		return -SOCKS105_ERROR_BUFFER;
	
	*data = htons(num);
	
	return 0;
}

/* does not free anything in case of failure */
static int auth_info_parse(struct bufstream *bs, struct socks105_auth_info *auth_info, int advert)
{
	uint8_t n_adverts = 0;
	uint8_t *adverts = NULL;
	int err;
	
	if (advert)
	{
		CHECK(byte_parse(bs, &n_adverts), err, fail);
		adverts = bufstream_take(bs, n_adverts * sizeof(uint8_t));
		if (!adverts)
			return -SOCKS105_ERROR_BUFFER;
	}
	
	uint8_t n_data;
	CHECK(byte_parse(bs, &n_data), err, fail);
	
	auth_info->count = n_adverts + n_data;
	auth_info->auth_data = malloc(auth_info->count * sizeof(struct socks105_auth_data));
	if (!auth_info->auth_data)
		return -SOCKS105_ERROR_ALLOC;
	bzero(auth_info->auth_data, auth_info->count * sizeof(struct socks105_auth_data));
	
	/* adverts */
	for (int i = 0; i < n_adverts; i++)
		auth_info->auth_data[i].method = adverts[i];
	
	for (int i = n_adverts; i < n_adverts + n_data; i++)
	{
		struct socks105_auth_data *auth_data = &auth_info->auth_data[i];
		CHECK(byte_parse(bs, &auth_data->method), err, fail);
		CHECK(byte_parse(bs, &auth_data->data_len), err, fail);
		
		uint8_t *data = bufstream_take(bs, auth_data->data_len * sizeof(uint8_t));
		if (!data)
			return -SOCKS105_ERROR_BUFFER;
		auth_data->data = malloc(auth_data->data_len);
		if (!auth_data->data)
			return -SOCKS105_ERROR_ALLOC;
		memcpy(auth_data->data, data, auth_data->data_len);
	}
	
	return 0;
	
fail:
	return err;
}

static int auth_info_pack(struct bufstream *bs, struct socks105_auth_info *auth_info)
{
	uint8_t n_adverts = 0;
	uint8_t n_data = 0;
	int err;
	
	/* inefficient, but fuck it! */
	for (int i = 0; i < (int)auth_info->count; i++)
	{
		struct socks105_auth_data *auth_data = &auth_info->auth_data[i];
		if (auth_data->data_len == 0)
			n_adverts++;
		else
			n_data++;
	}
	
	CHECK(byte_pack(bs, n_adverts), err, fail);
	for (int i = 0; i < (int)auth_info->count; i++)
	{
		struct socks105_auth_data *auth_data = &auth_info->auth_data[i];
		if (auth_data->data_len == 0)
			CHECK(byte_pack(bs, auth_data->method), err, fail);
	}
	
	CHECK(byte_pack(bs, n_data), err, fail);
	for (int i = 0; i < (int)auth_info->count; i++)
	{
		struct socks105_auth_data *auth_data = &auth_info->auth_data[i];
		if (auth_data->data_len != 0)
		{
			CHECK(byte_pack(bs, auth_data->method), err, fail);
			CHECK(byte_pack(bs, auth_data->data_len), err, fail);
			CHECK(blob_pack(bs, auth_data->data_len, auth_data->data), err, fail);
		}
	}
	
	return 0;
	
fail:
	return err;
}

static void auth_info_cleanup(struct socks105_auth_info *info)
{
	if (!info->auth_data)
		return;
	
	for (int i = 0; i < (int)info->count; i++)
	{
		if (info->auth_data[i].data)
			free(info->auth_data[i].data);
	}
	
	free(info->auth_data);
}

/* does not free anything in case of failure */
static int server_info_parse(struct bufstream *bs, struct socks105_server_info *server_info)
{
	int err;
	uint8_t domain_len;
	
	CHECK(byte_to_int_parse(bs, (int *)&server_info->addr_type), err, fail);
	
	switch (server_info->addr_type)
	{
	case SOCKS105_ADDR_IPV4:
		CHECK(ipv4_parse(bs, &server_info->addr.ipv4), err, fail);
		break;
		
	case SOCKS105_ADDR_IPV6:
		CHECK(ipv6_parse(bs, server_info->addr.ipv6), err, fail);
		break;
		
	case SOCKS105_ADDR_DOMAIN:
		CHECK(byte_parse(bs, &domain_len), err, fail);
		CHECK(blob_parse(bs, domain_len, (void **)&server_info->addr.domain, 1), err, fail);
		break;
		
	default:
		err = -SOCKS105_ERROR_INVALID;
		break;
	}
	
	CHECK(short_parse(bs, &server_info->port), err, fail);
	
	return 0;
	
fail:
	return err;
}

static int server_info_pack(struct bufstream *bs, struct socks105_server_info *server_info)
{
	int err;
	size_t domain_len;
	
	CHECK(byte_pack(bs, server_info->addr_type), err, fail);
	
	switch (server_info->addr_type)
	{
	case SOCKS105_ADDR_IPV4:
		CHECK(ipv4_pack(bs, server_info->addr.ipv4), err, fail);
		break;
		
	case SOCKS105_ADDR_IPV6:
		CHECK(ipv6_pack(bs, server_info->addr.ipv6), err, fail);
		break;
		
	case SOCKS105_ADDR_DOMAIN:
		domain_len = strlen(server_info->addr.domain);
		if (domain_len > 0xff)
		{
			err = -SOCKS105_ERROR_INVALID;
			goto fail;
		}
		CHECK(byte_pack(bs, domain_len), err, fail);
		CHECK(blob_pack(bs, domain_len, (void *)server_info->addr.domain), err, fail);
		break;
		
	default:
		err = -SOCKS105_ERROR_INVALID;
		break;
	}
	
	CHECK(short_pack(bs, server_info->port), err, fail);
	
	return 0;
	
fail:
	return err;
}

static void server_info_cleanup(struct socks105_server_info *server_info)
{
	if (server_info->addr_type == SOCKS105_ADDR_DOMAIN && server_info->addr.domain)
		free(server_info->addr.domain);
}

static int ver_sanity(uint8_t ver)
{
	if (ver != 105)
		return -SOCKS105_ERROR_OTHERVER;
	return 0;
}

static int req_type_sanity(enum socks105_req_type req_type)
{
	if (req_type != SOCKS105_REQ_TCP_CONNECT &&
		req_type != SOCKS105_REQ_TCP_LISTEN &&
		req_type != SOCKS105_REQ_UDP)
	{
		return -SOCKS105_ERROR_INVALID;
	}
	return 0;
}

static int irep_type_sanity(enum socks105_initial_reply_type irep_type)
{
	if (irep_type != SOCKS105_INITIAL_REPLY_SUCCESS &&
		irep_type != SOCKS105_INITIAL_REPLY_FAILURE)
	{
		return -SOCKS105_ERROR_INVALID;
	}
	return 0;
}

static int frep_type_sanity(enum socks105_final_reply_type frep_type)
{
	if (frep_type !=  SOCKS105_FINAL_REPLY_SUCCESS &&
		frep_type !=  SOCKS105_FINAL_REPLY_FAILURE &&
		frep_type !=  SOCKS105_FINAL_REPLY_NOT_ALLOWED &&
		frep_type !=  SOCKS105_FINAL_REPLY_NET_UNREACH &&                                                                              
		frep_type !=  SOCKS105_FINAL_REPLY_HOST_UNREACH &&                                                                             
		frep_type !=  SOCKS105_FINAL_REPLY_REFUSED &&                                                                                  
		frep_type !=  SOCKS105_FINAL_REPLY_TTL_EXPIRED &&                                                                              
		frep_type !=  SOCKS105_FINAL_REPLY_CMD_NOT_SUPPORTED &&                                                                        
		frep_type !=  SOCKS105_FINAL_REPLY_ADDR_NOT_SUPPORTED)
	{
		return -SOCKS105_ERROR_INVALID;
	}
	return 0;
}

static int tfo_sanity(uint8_t tfo)
{
	if (tfo != 0 && tfo != 1)
		return -SOCKS105_ERROR_INVALID;
	return 0;
}

ssize_t socks105_request_parse(void *buf, size_t buf_len, struct socks105_request **preq)
{
	int err;
	struct bufstream bs = { buf, buf_len };
	
	struct socks105_request *req = malloc(sizeof(struct socks105_request));
	if (!req)
		return -SOCKS105_ERROR_ALLOC;
	bzero(req, sizeof(struct socks105_request));
	
	/* version */
	uint8_t ver;
	CHECK(byte_parse(&bs, &ver), err, fail);
	CHECK(ver_sanity(ver), err, fail);
	
	/* auth info */
	CHECK(auth_info_parse(&bs, &req->auth_info, 1), err, fail);
	
	/* req type */
	CHECK(byte_to_int_parse(&bs, (int *)&req->req_type), err, fail);
	CHECK(req_type_sanity(req->req_type), err, fail);
	
	/* tfo */
	CHECK(byte_to_int_parse(&bs, &req->tfo), err, fail);
	CHECK(tfo_sanity(req->tfo), err, fail);
	
	/* server */
	CHECK(server_info_parse(&bs, &req->server_info), err, fail);
	
	/* initial data */
	CHECK(short_parse(&bs, &req->initial_data_size), err, fail);
	CHECK(blob_parse(&bs, req->initial_data_size, &req->initial_data, 0), err, fail);
	
	*preq = req;
	return buf_len - bs.len;
fail:
	socks105_request_delete(req);
	
	return err;
}

ssize_t socks105_request_pack(struct socks105_request *req, void *buf, size_t buf_len)
{
	int err;
	struct bufstream bs = { buf, buf_len };
	
	/* version */
	CHECK(byte_pack(&bs, 105), err, fail);
	
	/* auth info */
	CHECK(auth_info_pack(&bs, &req->auth_info), err, fail);
	
	/* req type */
	CHECK(req_type_sanity(req->req_type), err, fail);
	CHECK(byte_pack(&bs, req->req_type), err, fail);
	
	/* tfo */
	CHECK(tfo_sanity(req->tfo), err, fail);
	CHECK(byte_pack(&bs, req->tfo), err, fail);
	
	/* server */
	CHECK(server_info_pack(&bs, &req->server_info), err, fail);
	
	/* initial data */
	CHECK(short_pack(&bs, req->initial_data_size), err, fail);
	CHECK(blob_pack(&bs, req->initial_data_size, req->initial_data), err, fail);
	
	return buf_len - bs.len;
	
fail:
	return err;
}

void socks105_request_delete(struct socks105_request *req)
{
	auth_info_cleanup(&req->auth_info);
	server_info_cleanup(&req->server_info);
	if (req->initial_data)
		free(req->initial_data);
	free(req);
}

ssize_t socks105_initial_reply_parse(void *buf, size_t buf_len, struct socks105_initial_reply **pirep)
{
	int err;
	struct bufstream bs = { buf, buf_len };
	
	struct socks105_initial_reply *irep = malloc(sizeof(struct socks105_initial_reply));
	if (!irep)
		return -SOCKS105_ERROR_ALLOC;
	bzero(irep, sizeof(struct socks105_initial_reply));
	
	/* version */
	uint8_t ver;
	CHECK(byte_parse(&bs, &ver), err, fail);
	CHECK(ver_sanity(ver), err, fail);
	
	/* type */
	CHECK(byte_to_int_parse(&bs, (int *)&irep->irep_type), err, fail);
	CHECK(irep_type_sanity(irep->irep_type), err, fail);
	
	/* auth method */
	CHECK(byte_parse(&bs, &irep->method), err, fail);
	
	/* auth info */
	CHECK(auth_info_parse(&bs, &irep->auth_info, 0), err, fail);
	
	*pirep = irep;
	return buf_len - bs.len;
	
fail:
	socks105_initial_reply_delete(irep);
	return err;
}

void socks105_initial_reply_delete(struct socks105_initial_reply *irep)
{
	auth_info_cleanup(&irep->auth_info);
	free(irep);
}

ssize_t socks105_initial_reply_pack(struct socks105_initial_reply *irep, void *buf, size_t buf_len)
{
	int err;
	struct bufstream bs = { buf, buf_len };
	
	/* version */
	CHECK(byte_pack(&bs, 105), err, fail);
	
	/* irep type */
	CHECK(irep_type_sanity(irep->irep_type), err, fail);
	CHECK(byte_pack(&bs, irep->irep_type), err, fail);
	
	/* auth info */
	CHECK(auth_info_pack(&bs, &irep->auth_info), err, fail);
	
	return buf_len - bs.len;
	
fail:
	return err;
}

ssize_t socks105_final_reply_parse(void *buf, size_t buf_len, struct socks105_final_reply **pfrep)
{
	int err;
	struct bufstream bs = { buf, buf_len };
	
	struct socks105_final_reply *frep = malloc(sizeof(struct socks105_final_reply));
	if (!frep)
		return -SOCKS105_ERROR_ALLOC;
	bzero(frep, sizeof(struct socks105_final_reply));
	
	/* frep type */
	CHECK(byte_to_int_parse(&bs, (int *)&frep->frep_type), err, fail);
	CHECK(frep_type_sanity(frep->frep_type), err, fail);
	
	/* server */
	CHECK(server_info_parse(&bs, &frep->server_info), err, fail);
	
	/* data offset */
	CHECK(short_parse(&bs, &frep->data_offset), err, fail);
	
	*pfrep = frep;
	return buf_len - bs.len;
	
fail:
	socks105_final_reply_delete(frep);
	
	return err;
}

void socks105_final_reply_delete(struct socks105_final_reply *frep)
{
	server_info_cleanup(&frep->server_info);
	free(frep);
}

ssize_t socks105_final_reply_pack(struct socks105_final_reply *frep, void *buf, size_t buf_len)
{
	int err;
	struct bufstream bs = { buf, buf_len };
	
	/* frep type */
	CHECK(frep_type_sanity(frep->frep_type), err, fail);
	CHECK(byte_pack(&bs, frep->frep_type), err, fail);
	
	/* server */
	CHECK(server_info_pack(&bs, &frep->server_info), err, fail);
	
	/* data offset */
	CHECK(short_pack(&bs, frep->data_offset), err, fail);
	
	return buf_len - bs.len;
	
fail:
	return err;
}
