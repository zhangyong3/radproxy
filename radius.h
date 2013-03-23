
#ifndef RADIUS_H
#define RADIUS_H

typedef void RADIUS_CTX;

RADIUS_CTX *radius_parse(const void *data, int len, const char* secret, int check);

int radius_iseap(RADIUS_CTX *ctx);

int radius_has_attrib(RADIUS_CTX *ctx, int code, int vid, int vtype);

/*need call free*/
void *radius_get_attrib_val(RADIUS_CTX *ctx, int code, int vid, int vtype, int *outlen);


void radius_free(RADIUS_CTX *ctx);

int radius_is_authen_end(RADIUS_CTX *ctx);


int radius_check_sign(RADIUS_CTX *ctx, const char *secret);

int radius_sign(const char *secret, unsigned char **pack, int *pack_len);

int radius_modify_raw_packet(int is_req, unsigned char *req, int req_len, const char *req_secret,
						unsigned char *resp, int resp_len, const char *resp_secret);

const char *radius_make_status_server_packet(void *buf, int *len, const char *secret);

const char *radius_get_secret(RADIUS_CTX *ctx);

#endif

