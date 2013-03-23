#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "radius.h"
#include "md5.h"


struct radius_hdr
{
	unsigned char code;
	unsigned char len;
	unsigned char val[0];
};

struct radius_mod_data
{
	const unsigned char *data;
	int data_len;

	int pack_type;
	int pack_id;
	int pack_len;
	const unsigned char *authenticator;

	int *attr_offset;
	int attr_used;
	int attr_size;

	char *secret;
};


static int radius_check(const void *data, int len)
{
	unsigned char *p = (unsigned char *)data;
	int pos = 0;
	if (len < 20)
		return -1;

	int pack_len = (((int)p[2]) << 8) | p[3];
	if (pack_len > len)
		return -2;

	pos = 20;
	while (pos < pack_len) {
		struct radius_hdr *h = (struct radius_hdr*)(p+pos);
		if (pack_len-pos<2)
			return -3;

		if (h->len < 2)
			return -4;

		if (h->code == 26 && h->len < 8)
			return -5;

		pos += h->len;
	}

	return 0;
}

RADIUS_CTX *radius_parse(const void *data, int data_len, const char* secret, int check)
{
	struct radius_mod_data *mod;
	unsigned char *p = (unsigned char *)data;
	int pos = 0;

	if (check && radius_check(data, data_len) !=0)
		return NULL;

	if (data_len < 20)
		return NULL;

	mod = (struct radius_mod_data*)calloc(1, sizeof(*mod));
	if (!mod)
		return NULL;

	mod->data = data;
	mod->data_len = data_len;

	mod->pack_type = p[0];
	mod->pack_id = p[1];
	mod->pack_len = (((int)p[2]) << 8) | p[3];
	mod->authenticator = p+4;

	if (mod->pack_len > data_len) {
		free(mod);
		return NULL;
	}

	mod->secret = strdup(secret);

	pos += 20;
	while (pos < mod->pack_len) {
		struct radius_hdr *h = (struct radius_hdr *)(p+pos);
		if (pos + h->len > mod->pack_len)
			break;

		if (mod->attr_used >= mod->attr_size) {
			int *new_attr_offset = realloc(mod->attr_offset, (mod->attr_size+8)*sizeof(int));
			if (!new_attr_offset)
				break;

			mod->attr_offset = new_attr_offset;
			mod->attr_size = mod->attr_size+8;
		}
		mod->attr_offset[mod->attr_used++] = pos;
		pos += h->len;
	}

	return mod;
}

int radius_iseap(RADIUS_CTX *ctx)
{
	return radius_has_attrib(ctx, 80, -1, -1) && radius_has_attrib(ctx, 79,-1,-1);
}

int radius_has_attrib(RADIUS_CTX *ctx, int code, int vendor_id, int vtype)
{
	int i;
	struct radius_mod_data *mod = (struct radius_mod_data*)ctx;
	if (!mod)
		return 0;

	if (!mod->attr_offset)
		return 0;

	for (i = 0; i < mod->attr_used; ++i) {
		struct radius_hdr *h = (struct radius_hdr *)(mod->data + mod->attr_offset[i]);
		if (h->code != code)
			continue;

		if (h->code == 26) {
			if (h->len <= 8)
				continue;

			int vid = 0;
			int j = 0;
			for (j = 0; j < 4; j++) {
				vid = vid << 8 | h->val[2+j];
			}
			if (vid != vendor_id)
				continue;

			unsigned char *p = (unsigned char *)(mod->data + mod->attr_offset[i]);
			unsigned char *q = p+6;
			while (q < p+h->len) {
				struct radius_hdr *h1 = (struct radius_hdr *)q;
				if (h1->code == vtype) {
					return 1;
				}
				q += h1->len;
			}
		}

		return 1;
	}

	return 0;
}

void *radius_get_attrib_val(RADIUS_CTX *ctx, int code, int vendor_id, int vtype, int *outlen)
{
	int i;
	struct radius_mod_data *mod = (struct radius_mod_data*)ctx;
	struct radius_hdr *cp = NULL;
	char *val;
	if (!mod)
		return NULL;

	if (!mod->attr_offset)
		return NULL;

	for (i = 0; i < mod->attr_used; ++i) {
		struct radius_hdr *h = (struct radius_hdr *)(mod->data + mod->attr_offset[i]);
		if (h->code != code)
			continue;

		if (h->code == 26) {
			if (h->len <= 8)
				continue;

			int vid = 0;
			int j = 0;
			for (j = 0; j < 4; j++) {
				vid = vid << 8 | h->val[2+j];
			}
			if (vid != vendor_id)
				continue;

			unsigned char *p = (unsigned char *)(mod->data + mod->attr_offset[i]);
			unsigned char *q = p+6;
			while (q < p+h->len) {
				struct radius_hdr *h1 = (struct radius_hdr *)q;
				if (h1->code == vtype) {
					cp = h1;
					goto ok;
				}
				q += h1->len;
			}
		}

		cp = h;
		goto ok;
	}

	return NULL;

ok:
	if (!cp || cp->len <=2)
		return NULL;

	val = malloc(cp->len-2);
	if (val) {
		memcpy(val, cp->val, cp->len-2);
		*outlen = cp->len-2;
	}
	return val;
}


void radius_free(RADIUS_CTX *ctx)
{
	struct radius_mod_data *mod = (struct radius_mod_data*)ctx;
	int i;
	if (!mod)
		return;

	if (mod->attr_offset)
		free(mod->attr_offset);
	mod->attr_offset = NULL;

	free(mod->secret);
	free(mod);
}

int radius_is_authen_end(RADIUS_CTX *ctx)
{
	struct radius_mod_data *mod = (struct radius_mod_data*)ctx;
	if (!mod)
		return 0;

	return mod->pack_type == 2 || mod->pack_type == 3;
}

int radius_sign(const char *secret, unsigned char **pack, int *pack_len)
{
	struct radius_mod_data *mod;
	RADIUS_CTX *ctx;
	if (!pack || !*pack || !pack_len)
		return -1;

	ctx = radius_parse(*pack, *pack_len, secret, 0);
	if (!ctx)
		return -2;

	mod = (struct radius_mod_data*)ctx;
	if (radius_has_attrib(ctx, 80, -1, -1)) {
		int i = 0;
		for (; i < mod->attr_used; ++i) {
			struct radius_hdr *h = (struct radius_hdr*)(mod->data + mod->attr_offset[i]);
			if (h->code == 80 && h->len == 18) {
				memset(h->val, 0, 16);
				lrad_hmac_md5(mod->data, mod->pack_len, secret, strlen(secret), h->val);

				radius_free(ctx);
				return 0;
			}
		}
	} else {
		int len = mod->pack_len;
		unsigned char* new_data = realloc(*pack, len+18);
		if (new_data) {
			new_data[len] = 80;
			new_data[len+1] = 18;
			memset(new_data+2, 0, 16);
			lrad_hmac_md5(new_data, len+18, secret, strlen(secret), new_data+len+2);

			len += 18;
			*pack = new_data;
			*pack_len = len+18;

			new_data[2] = len>>8;
			new_data[3] = len&0xff;

			radius_free(ctx);
			return 0;
		}
	}

	radius_free(ctx);
	return -2;
}

int radius_check_sign(RADIUS_CTX *ctx, const char *secret)
{
	int i = 0;
	struct radius_mod_data *mod = (struct radius_mod_data*)ctx;
	if (!mod)
		return -1;

	if (!secret)
		return -2;

	if (!radius_has_attrib(ctx, 80, -1, -1))
		return -3;

	for (;i < mod->attr_used; i++) {
		struct radius_hdr *h = (struct radius_hdr*)(mod->data + mod->attr_offset[i]);
		if (h->code == 80 && h->len == 18) {
			unsigned digest[16];
			unsigned digest2[16];

			memcpy(digest, h->val, 16);
			memset(h->val, 0, 16);
			lrad_hmac_md5(mod->data, mod->pack_len, secret, strlen(secret), digest2);
			if (memcmp(digest, digest2, 16) != 0)
				return -4;

			break;
		}
	}

	return 0;
}



static int radius_encode_password(void *pass, const void *plain, int plain_len, const void *RA, const char *S)
{
	int i,j;
	int len;
	unsigned char b[16];
	unsigned char *c = (unsigned char *)pass;
	unsigned char *p = (unsigned char *)plain;

	char s0[128]; 
	int lenS = strlen(S); 

	if (!pass)
		return -1;
	if (!plain || plain_len <= 0)
		return -2;
	if (!RA || !S)
		return -3;

	if (lenS+16 > sizeof(s0))
		return -4;

	memcpy(s0, S, lenS);
	memcpy(s0 + lenS, RA, 16);
	md5_calc(b, s0, lenS + 16);


	len = 16 * ((plain_len + 15) / 16);
	for (i = 0; i < len; i += 16) {
		unsigned char x[16];
		if (plain_len-i >= 16) {
			memcpy(x, p+i, 16);
		} else {
			memset(x, 0, sizeof(x));
			memcpy(x, p+i, plain_len-i);
		}

		for (j = 0; j < 16; ++j) {
			c[j] = x[j] ^ b[j];
		}

		memcpy(s0 + lenS, c, 16);
		md5_calc(b, s0, lenS + 16);

		c += 16;
		p += 16;
	}

	return i;
}

static int radius_decode_password(void *plain, const void *pass, int pass_len, const void *RA, const char *S)
{
	unsigned char b[16];
	unsigned char *c = (unsigned char *)pass;
	unsigned char *p = (unsigned char *)plain;

	int i,j;
	int lenS = strlen(S);
	char s0[128];

	if (!plain)
		return -1;
	if (!pass || pass_len <= 0)
		return -2;
	if (!RA || !S)
		return -3;

	if (pass_len % 16 != 0)
		return -4;

	if (lenS+16 > sizeof(s0))
		return -5;

	memcpy(s0, S, lenS);
	memcpy(s0 + lenS, RA, 16);

	md5_calc(b, s0, lenS + 16);
	for (i = 0; i < pass_len; i += 16) {
		for (j = 0; j < 16; ++j) {
			p[j] = c[j] ^ b[j];
		}

		memcpy(s0 + lenS, c, 16);
		md5_calc(b, s0, lenS + 16);

		c += 16;
		p += 16;
	}

	return i;
}


int radius_modify_raw_packet(int is_req, unsigned char *req, int req_len, const char *nas_secret,
			unsigned char *resp, int resp_len, const char *radius_secret)
{
	if (is_req) {
		int pos = 0;
		if (!req || req_len < 20)
			return -1;

		if (req[0] == 1) {
			pos = 20;
			while (pos < req_len) {
				struct radius_hdr *h = (struct radius_hdr*)(req+pos);
				if (req_len -pos <= 2)
					return -2;
				if (h->code == 2) {
					if ((h->len-2)%16 == 0) {
						char pass[256];
						char pass_new[256];
						int pass_len = radius_decode_password(pass, h->val, h->len-2, req+4, nas_secret);
						int pass_len_new = radius_encode_password(pass_new, pass, pass_len, req+4, radius_secret);
						if (pass_len_new == h->len-2) {
							memcpy(h->val, pass_new, h->len-2);
							return 0;
						}
					}
					break;
				}

				pos += h->len;
			}
		} else if (req[0] == 4) {
			MD5_CTX ctx;
			MD5Init(&ctx);

			unsigned char authenticator[16];
			memcpy(authenticator, req+4, 16);
			memset(req+4, 0, 16);

			MD5Update(&ctx, req, req_len);
			MD5Update(&ctx, radius_secret, strlen(radius_secret));
			MD5Final(authenticator, &ctx);
			memcpy(req+4, authenticator, 16);
		}
	} else {
		MD5_CTX ctx;
		unsigned char authenticator[16];

		if (!req || req_len < 20)
			return -1;

		if (!resp || resp_len < 20)
			return -2;

		memcpy(authenticator, req+4, 16);

		MD5Init(&ctx);
		memcpy(resp+4, authenticator, 16);
		MD5Update(&ctx, resp, resp_len);
		MD5Update(&ctx, nas_secret, strlen(nas_secret));
		MD5Final(authenticator, &ctx);

		memcpy(resp+4, authenticator, 16);
	}
	return 0;
}

const char *radius_make_status_server_packet(void *buf, int *len, const char *secret)
{
	int i = 0;
	static unsigned char id = 0;
	unsigned char *p;
	if (!buf || !len)
		return NULL;

	if (*len < 38)
		return NULL;

	p = buf;
	p[0] = 12;
	p[1] = id++;
	p[2] = 0;
	p[3] = 38;
	p[20] = 80;
	p[21] = 18;

	for (i = 0; i < 16; ++i) {
		p[4+i] = rand()%256;
	}

	memset(p+22, 0, 16);
	lrad_hmac_md5(p, 38, secret, strlen(secret), p+22);
	*len = 38;
	return buf;
}

const char *radius_get_secret(RADIUS_CTX *ctx)
{
	struct radius_mod_data *mod = (struct radius_mod_data*)ctx;
	if (mod)
		return mod->secret;

	return NULL;
}
