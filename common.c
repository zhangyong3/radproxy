#include <stdio.h>
#include <string.h>
#include "common.h"
#include "radproxy.h"
#include "hash.h"


int radproxy_ipaddr2sockaddr(const struct radproxy_addr *ipaddr,
	struct  sockaddr_storage *sa, socklen_t *salen)
{
	if (ipaddr->af == AF_INET) {
		struct sockaddr_in s4;

		*salen = sizeof(s4);

		memset(&s4, 0, sizeof(s4));
		s4.sin_family = AF_INET;
		s4.sin_addr = ipaddr->ip.ip4;
		s4.sin_port = htons(ipaddr->port);
		memset(sa, 0, sizeof(*sa));
		memcpy(sa, &s4, sizeof(s4));
	} else if (ipaddr->af == AF_INET6) {
		struct sockaddr_in6 s6;

		*salen = sizeof(s6);

		memset(&s6, 0, sizeof(s6));
		s6.sin6_family = AF_INET6;
		s6.sin6_addr = ipaddr->ip.ip6;
		s6.sin6_port = htons(ipaddr->port);
		memset(sa, 0, sizeof(*sa));
		memcpy(sa, &s6, sizeof(s6));
	} else {
		return -1;
	}

	return 0;
}

int radproxy_sockaddr2ipaddr(const struct  sockaddr_storage *sa,
		struct radproxy_addr *ipaddr)
{
	if (sa->ss_family == AF_INET) {
		struct sockaddr_in *s4 = (struct sockaddr_in *)sa;
		ipaddr->af = AF_INET;
		ipaddr->ip.ip4 = s4->sin_addr;
		ipaddr->port = ntohs(s4->sin_port);
	} else if (sa->ss_family == AF_INET6) {
		struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)sa;
		ipaddr->af = AF_INET6;
		memcpy(&ipaddr->ip.ip6, &s6->sin6_addr, sizeof(s6->sin6_addr));
		ipaddr->port = ntohs(s6->sin6_port);
	} else {
		return -1;
	}
	return 0;
}

char *radproxy_ipaddr_str(const struct radproxy_addr *ipaddr, char *buf, int buflen)
{
	char port_buf[16];
	int n = sprintf(port_buf, "%d", ipaddr->port);

	if (ipaddr->af == AF_INET) {
		inet_ntop(ipaddr->af, &ipaddr->ip.ip4, buf, buflen-n-2);
		strcat(buf, ":");
	} else if (ipaddr->af == AF_INET6) {
		inet_ntop(ipaddr->af, &ipaddr->ip.ip6, buf, buflen-n-2);
		strcat(buf, ".");
	}
	strcat(buf, port_buf);

	return buf;
}

int radproxy_name2addr(const char *name, struct radproxy_addr* addr)
{
	memset(addr, 0, sizeof(*addr));
	char ipbuf[128];
	if (strlen(name) >= sizeof(ipbuf))
		return -1;

	strncpy(ipbuf, name, sizeof(ipbuf)-1);
	char *ip = ipbuf;
	char *inf = strchr(ipbuf, '%');
	if (inf != NULL)
		*inf++ = '\0';

	struct addrinfo *res = NULL;
	if (0 != getaddrinfo(ip, NULL, NULL, &res)) {
		return -2;
	}

	struct addrinfo *p =  res;
	while (p) {
		if (p->ai_family == AF_INET) {
			struct sockaddr_in *s = (struct sockaddr_in *)p->ai_addr;
			addr->af = AF_INET;
			memcpy(&addr->ip.ip4, &s->sin_addr, sizeof(addr->ip.ip4));
			break;
		} else if (p->ai_family == AF_INET6) {
			struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)p->ai_addr;
			addr->af = AF_INET6;
			memcpy(&addr->ip.ip6, &s6->sin6_addr, sizeof(addr->ip.ip6));
			break;
		}
		p = p->ai_next;
	}

	freeaddrinfo(res);
	if (p == NULL) {
		return -3;
	}

	return 0;
}


int radproxy_time_diff(struct timeval *tv1, struct timeval *tv2)
{
	int sec = tv1->tv_sec - tv2->tv_sec;
	int usec = tv1->tv_usec - tv2->tv_usec;
	if (usec < 0) {
		usec += 1000000;
		sec -= 1;
	}

	if (sec < 0)
		return 0;

	return sec*1000 + usec/1000;
}


uint32_t hash_state(const void *data)
{
	const struct radius_state_node *p = data;
	return fr_hash(p->data, p->datalen);
}

int hash_state_cmp(const void *a, const void *b)
{
	const struct radius_state_node *p1 = a;
	const struct radius_state_node *p2 = b;

	if (p1->datalen != p2->datalen)
		return p1->datalen - p2->datalen;

	return memcmp(p1->data, p2->data, p1->datalen);
}


/*
int addr_segment_cmp(struct addr_segment *a, struct addr_segment *b)
{
	return 0;
}


int half_search(void **array, int array_len, const void *data, half_cmp_fn cmp)
{
	int min = 0;
	int max = array_len - 1;

	while (min <= max) {
		int mid = (min+max)/2;
		int i = cmp(array[mid], data);
		if (i == 0)
			return mid;
		else if (i < 0) {
			min = mid;
		} else {
			max = mid;
		}
	}

	return -1;
}
*/

struct addr_segment *radproxy_ipaddr2segment(struct addr_segment *s, const struct radproxy_addr *ipaddr)
{
	int loop = 0;
	s->ipv4 = (ipaddr->af == AF_INET);
	if (s->ipv4)
		loop = 4;
	else
		loop = 16;

	while (loop-- > 0) {
		s->seg[loop].start = ipaddr->ip.b[loop];
		s->seg[loop].end = ipaddr->ip.b[loop];
	}

	return s;
}

