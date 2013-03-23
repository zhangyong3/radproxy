#ifndef _COMMON_H
#define _COMMON_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/inet.h>
#include <netdb.h>

struct radproxy_addr
{
	int af;
	union
	{
		struct in_addr ip4;
		struct in6_addr ip6;
		unsigned char b[16];
	} ip;
	unsigned short port;
};

int radproxy_ipaddr2sockaddr(const struct radproxy_addr *ipaddr,
			struct  sockaddr_storage *sa, socklen_t *salen);

int radproxy_sockaddr2ipaddr(const struct  sockaddr_storage *sa,
				struct radproxy_addr *ipaddr);

char *radproxy_ipaddr_str(const struct radproxy_addr *ipaddr, char *buf, int buflen);

int radproxy_name2addr(const char *name, struct radproxy_addr* addr);

int radproxy_time_diff(struct timeval *tv1, struct timeval *tv2);

uint32_t hash_state(const void *data);

int hash_state_cmp(const void *a, const void *b);


struct int_segment
{
	unsigned int start;
	unsigned int end;
};

struct addr_segment
{
	int ipv4;
	struct int_segment seg[16];
};

/*
int addr_segment_cmp(struct addr_segment *a, struct addr_segment *b);
typedef int (*half_cmp_fn)(const void *, const void *);
int half_search(void **array, int array_len, const void *data, half_cmp_fn cmp);
*/

struct addr_segment *radproxy_ipaddr2segment(struct addr_segment *s, const struct radproxy_addr *ipaddr);

#endif
