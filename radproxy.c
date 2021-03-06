#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/epoll.h>
#include "common.h"
#include "radproxy.h"
#include "cfgparse.h"
#include "radius.h"
#include "log.h"

extern int mainLoop;

void radproxy_destroy(struct radproxy_data *data);

static void radproxy_clear_sm(struct radproxy_sm *sm)
{
	if (sm->req) {
		free(sm->req);
		sm->req = NULL;
	}
	sm->req_len = 0;

	if (sm->resp) {
		free(sm->resp);
		sm->resp = NULL;
	}
	sm->resp_len = 0;
	if (sm->fd_remote > 0) {
		close(sm->fd_remote);
		sm->fd_remote = -1;
	}

	if (sm->radius_ctx) {
		radius_free(sm->radius_ctx);
		sm->radius_ctx = NULL;
	}

	sm->failover = 0;
	sm->from = NULL;
	sm->serv = NULL;
	memset(&sm->node, 0, sizeof(sm->node));
	memset(&sm->active_node, 0, sizeof(sm->active_node));
	memset(&sm->free_node, 0, sizeof(sm->free_node));
}

static void radproxy_destroy_sm(struct radproxy_desc *proxy, struct radproxy_sm *sm)
{
	log_debug("[%d] destroyed\n", sm->id);
	if (sm->serv) {
		dlist_remove(&sm->serv->sm_list, &sm->active_node);
	}

	dlist_remove(&proxy->sms, &sm->node);
	radproxy_clear_sm(sm);

	dlist_append(&proxy->freesms, &sm->free_node);
}

static struct radproxy_sm* radproxy_new_sm(struct radproxy_desc *proxy)
{
	struct radproxy_sm *sm = NULL;
	dlist_node_t *node = dlist_remove_head(&proxy->freesms);

	if (node != NULL)
		sm = dlist_get_struct_ptr(struct radproxy_sm, free_node, node);

	if (sm) {
		radproxy_clear_sm(sm);
	} else {
		sm = calloc(1, sizeof(*sm));
		if (!sm)
			return NULL;
	}

	dlist_append(&proxy->sms, &sm->node);
	sm->id = proxy->sm_id++;

	return sm;
}


static int radproxy_sendto(int fd, const void *data, int data_len, struct radproxy_addr *to)
{
	struct sockaddr_storage ss;
	int size_ss = sizeof(ss);
	radproxy_ipaddr2sockaddr(to, &ss, &size_ss);

	return sendto(fd, data, data_len, 0, (struct sockaddr*)&ss, size_ss);
}

static int radproxy_recvfrom(int fd, void *data, int data_len, struct radproxy_addr *from)
{
	struct sockaddr_storage ss;
	socklen_t size_ss = sizeof(ss);
	int len = 0;

	len = recvfrom(fd, data, data_len, 0, (struct sockaddr*)&ss, &size_ss);
	radproxy_sockaddr2ipaddr(&ss, from);
	return len;
}

static const char *radproxy_get_client_secret(struct radproxy_client *clients, const struct radproxy_addr *addr)
{
	struct radproxy_client *c = NULL;
	if (!clients)
		return "";

	for (c = clients; c; c = c->next) {
		int loop = 16;
		if (c->addr_seg->ipv4 && addr->af != AF_INET)
			continue;

		if (!c->addr_seg->ipv4 && addr->af != AF_INET6)
			continue;

		if (c->addr_seg->ipv4)
			loop = 4;

		while (loop-- > 0) {
			if (addr->ip.b[loop] > c->addr_seg->seg[loop].end ||
				addr->ip.b[loop] < c->addr_seg->seg[loop].start)
				break;
		}

		if (loop == -1)
			break;
	}

	return c? c->secret : "";
}

static int radproxy_init_server(struct radproxy_data *data)
{
	int i = 0;
	struct addrinfo *res, *aip;
	struct addrinfo hints;
	//char hostname[64];
	int flags = 1;
	struct radproxy_desc *p;
	int number_of_listener = 0;

	//if (0 != gethostname(hostname, sizeof(hostname)))
	//	return -4;

	for (p = data->proxys; p ; p=p->next) {
		char port_buf[16];

		dlist_init(&p->sms);
		dlist_init(&p->freesms);
		dlist_init(&p->listens);

		memset(&hints, 0, sizeof(hints));
		hints.ai_flags = AI_PASSIVE;
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_DGRAM;
		sprintf(port_buf, "%d", p->port);

		if (0 != getaddrinfo(NULL, port_buf, &hints, &res)) {
			perror("getaddrinfo");
			return -2;
		}
		p->epfd = epoll_create(128);
		if (p->epfd < 0) {
			perror("epoll_create");
			return -3;
		}

		for (aip =  res; aip != NULL; aip = aip->ai_next) {
			struct radproxy_sm *sm;
			char ipbuf[64];
			struct radproxy_listen_interface *lf;

#ifdef NOIPV6
			if (aip->ai_family == AF_INET6)
				continue;
#endif
			int fd = socket(aip->ai_family, aip->ai_socktype, aip->ai_protocol);
			if (fd < 0)
				continue;

			setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&flags, sizeof(flags));
			if (bind(fd, aip->ai_addr, aip->ai_addrlen) == -1) {
				perror("bind()");
				close(fd);
				break;
			}

			lf = calloc(1, sizeof(*lf));
			if (!lf) {
				close(fd);
				break;
			}

			lf->fd = fd;
			radproxy_sockaddr2ipaddr((const struct  sockaddr_storage *)aip->ai_addr, &lf->addr);

			radproxy_ipaddr_str(&lf->addr, ipbuf, sizeof(ipbuf));
			log_info("radproxy is serving at %s, fd=%d\n", ipbuf, fd);

			sm = radproxy_new_sm(p);
			if (sm) {
				struct epoll_event ee;
				sm->state = local_listen;
				sm->from = lf;
				ee.events = EPOLLIN;
				ee.data.ptr = sm;
				epoll_ctl(p->epfd, EPOLL_CTL_ADD, fd, &ee);

				dlist_append(&p->listens, &lf->node);
			} else {
				free(lf);
				close(fd);
			}
		}
		freeaddrinfo(res);

		p->clients = data->clients;
		number_of_listener += dlist_size(&p->listens);

		for (i = 0; i < p->server_cnt; ++i) {
			struct radproxy_backend_server *sv = p->servers[i];
			if (sv != NULL) {
				dlist_init(&sv->sm_list);
			}
		}
	}

	if (number_of_listener <= 0) {
		fprintf(stderr, "no listen socket created\n");
		return -4;
	}

	return 0;
}

static void radproxy_close_proxy(struct radproxy_desc *p)
{
	dlist_node_t *n = NULL;
	while ((n = dlist_remove_head(&p->listens)) != NULL) {
		struct radproxy_listen_interface *lf;
		lf = dlist_get_struct_ptr(struct radproxy_listen_interface, node, n);
		close(lf->fd);
	}
}


static struct radproxy_sm *radproxy_process_new_req(
		struct radproxy_desc *p, struct radproxy_sm *sm)
{
	char buf[4096];
	struct radproxy_addr addr;
	int fd = sm->from->fd;
	int len = radproxy_recvfrom(fd, buf, sizeof(buf), &addr);
	if (len <= 0)
		return NULL;

	struct radproxy_sm *new_sm = radproxy_new_sm(p);
	if (new_sm) {
		char ipbuf[64];
		new_sm->req = malloc(len);
		if (!new_sm->req) {
			radproxy_destroy_sm(p, new_sm);
			return NULL;;
		}

		memcpy(new_sm->req, buf, len);
		new_sm->req_len = len;
		memcpy(&new_sm->local_addr, &sm->from->addr, sizeof(new_sm->local_addr));
		memcpy(&new_sm->from_addr, &addr, sizeof(addr));
		gettimeofday(&new_sm->tv, NULL);
		new_sm->from = sm->from;
		new_sm->state = remote_write;

		log_debug("[%d] new packet from %s\n", new_sm->id,
			radproxy_ipaddr_str(&addr, ipbuf, sizeof(ipbuf)));
		return new_sm;
	}

	return NULL;
}

static void radproxy_process_failover(time_t now, struct radproxy_desc *p)
{
	int i = 0;
	if (!(p->option & OPTION_FAILOVER))
		return;

	for (i = 0; i < p->server_cnt; ++i) {
		int create_ok = 0;
		struct radproxy_sm *sm;
		struct radproxy_backend_server *s = p->servers[i];

		if (s->is_checking)
			return;

		if (now - s->last_check < p->interv)
			return;

		sm = radproxy_new_sm(p);
		if (!sm)
			return;

		sm->req = malloc(64);
		sm->req_len = 64;
		if (sm->req && radius_make_status_server_packet(sm->req, &sm->req_len, s->secret)) {
			int fd = socket(s->addr.af, SOCK_DGRAM, 0);
			if (fd > 0) {
				struct epoll_event ee;
				sm->fd_remote = fd;

				gettimeofday(&sm->tv, NULL);
				memcpy(&sm->dest_addr, &s->addr, sizeof(s->addr));
				sm->maxtry = p->maxtry;
				sm->failover = 1;
				sm->state = remote_write;
				sm->p = p;
				sm->serv = s;
				create_ok = 1;
				s->is_checking = 1;

				dlist_append(&s->sm_list, &sm->active_node);
				ee.events = EPOLLOUT;
				ee.data.ptr = sm;
				epoll_ctl(p->epfd, EPOLL_CTL_ADD, fd, &ee);
				log_debug("[%d] start a health check\n", sm->id);
			}
		}

		if (!create_ok)
			radproxy_destroy_sm(p, sm);
	}
}

static struct radius_state_node *create_radius_state_node(const void *state, int len, struct radproxy_backend_server *srv)
{
	struct radius_state_node *p;
	p = malloc(sizeof(*p));
	if (!p)
		return NULL;

	p->data = malloc(len);
	if (!p->data) {
		free(p);
		return NULL;
	}

	memcpy(p->data, state, len);
	p->datalen = len;
	p->serv = srv;
	p->create_tm = time(0);

	return p;
}

static void free_radius_state_node(struct radius_state_node *p)
{
	if (p) {
		if (p->data)
			free(p->data);
		free(p);
	}
}

static int radproxy_remove_timeout_state(void *ctx, void *data)
{
	struct radproxy_desc *p = ctx;
	struct radius_state_node *d = data;

	if (time(0) - d->create_tm  > p->state_timeout) {
		log_debug("delete timeout state\n");
		fr_hash_table_delete(p->ht_state, d);
		free_radius_state_node(d);
		return 1;/*this cause ht stop recurse*/
	}

	return 0;
}

struct radproxy_backend_server *radproxy_apply_start(
		struct radproxy_desc *p, struct radproxy_sm *sm)
{
	if (p->mode == mode_radius) {
		int is_eap_packet = 0;
		const char *from_key = radproxy_get_client_secret(p->clients, &sm->from_addr);
		RADIUS_CTX *ctx = radius_parse(sm->req, sm->req_len, from_key,
				p->option & OPTION_PACK_CHECK);

		if (!ctx) {
			log_info("[%d] malformed radius packet\n", sm->id);
			return NULL;
		}

		if (p->option & OPTION_SIGN) {
			if (radius_check_sign(ctx, from_key) != 0) {
				log_info("[%d] check eap-authenticator error\n", sm->id);
				radius_free(ctx);
				return NULL;
			}
		}

		sm->radius_ctx = ctx;
		if (p->option & OPTION_STATE) {
			int state_len = 0;
			/*remove timeout*/
			void *state_data = NULL;
			if (p->ht_state)
				fr_hash_table_walk(p->ht_state, radproxy_remove_timeout_state, p);

			/*check if packet has State, forward it by check hashtable*/
			state_data = radius_get_attrib_val(ctx, 24, -1, -1, &state_len);
			if (state_data != NULL) {
				struct radproxy_backend_server *s = NULL;
				struct radius_state_node *n = create_radius_state_node(state_data, state_len, NULL);

				if (n) {
					struct radius_state_node *history = fr_hash_table_finddata(p->ht_state, n);

					free_radius_state_node(n);
					if (history) {
						s = history->serv;
					} else {
						log_debug("[%d] server not found by state\n", sm->id);
					}
				}

				free(state_data);
				if (s) {
					log_debug("[%d] server [%s] found by state\n", sm->id, s->name);
					sm->serv = s;
					return s;
				}
			}

			/*parse packet find eap-message, eap-authenticator, if true, set is_eap_packet =1*/
			is_eap_packet = radius_iseap(ctx);

			if (p->option & OPTION_ROUND_ROBIN) {
				struct radproxy_backend_server *s = NULL;
				int i = 0, j = 0;
				int prev = p->cur;
				for (i =0; i<p->server_cnt; ++i) {
					j = (++prev)% p->server_cnt;

					s = p->servers[j];
					if (s->status == 1) { /*server down*/
						continue;
					}

					if (is_eap_packet && (s->option & OPTION_STATE)) {
						break;
					}

					if (!is_eap_packet && (s->option & OPTION_NO_STATE)) {
						break;
					}

					if (!(s->option & OPTION_STATE) && !(s->option & OPTION_NO_STATE)) {
						break;
					}
				}

				if (i == p->server_cnt) {
					log_debug("[%d] no backend server available\n", sm->id);
					return NULL;
				}

				p->cur = j;
				sm->serv = s;
				return s;
			} else if (p->option & OPTION_SOURCE) {
				//TODO
			}
		} else {
			/*ok, this is easy, never worry about state*/
			struct radproxy_backend_server *s = NULL;
			int i = 0, j = p->cur;
			for (i =0; i<p->server_cnt; ++i) {
				j = (j+1) % p->server_cnt;
				if (p->servers[j]->status == 1) { /*server down*/
					continue;
				}

				p->cur = j;
				break;
			}

			if (i == p->server_cnt) {
				log_debug("[%d] no backend server available\n", sm->id);
				return NULL;
			}

			sm->serv = p->servers[j];
			return p->servers[j];
		}
	}

	return NULL;
}

static void radproxy_apply_finish(struct radproxy_desc *p, struct radproxy_sm *sm)
{
	if (p->mode == mode_radius) {
		if (!sm->resp || !sm->serv)
			return;

		struct RADIUS_CTX *resp_ctx = radius_parse(sm->resp, sm->resp_len, sm->serv->secret, 0);
		if (sm->radius_ctx && resp_ctx) {
			char *state;
			int statelen = 0;
			int req_has_state = radius_has_attrib(sm->radius_ctx, 24, -1, -1);
			int resp_has_state = radius_has_attrib(resp_ctx, 24, -1, -1);
			if (!req_has_state && resp_has_state) {
				state = radius_get_attrib_val(resp_ctx, 24, -1, -1, &statelen);
				if (state) {
					struct radius_state_node *n = create_radius_state_node(state, statelen, sm->serv);
					if (n) {
						if (1 == fr_hash_table_insert(p->ht_state, n)) {
							log_debug("insert by state\n");
						} else {
							free_radius_state_node(n);
						}
					}
					free(state);
				}
			}

			if (req_has_state && !resp_has_state && radius_is_authen_end(resp_ctx)) {
				state = radius_get_attrib_val(sm->radius_ctx, 24, -1, -1, &statelen);
				if (state) {
					struct radius_state_node *n = create_radius_state_node(state, statelen, sm->serv);
					if (n) {
						log_debug("delete state\n");
						fr_hash_table_delete(p->ht_state, n);
						free_radius_state_node(n);
					}
					free(state);
				}
			}
		}

		if (p->option & OPTION_SIGN) {
			radius_sign(sm->serv->secret, &sm->resp, &sm->resp_len);
		}

		radius_free(resp_ctx);
	}
}

void radproxy_modify_packet(struct radproxy_sm *sm, int is_req)
{
	int ret;
	const char *from_secret;
	const char *to_secret;
	if (sm->failover)
		return;

	from_secret = radius_get_secret(sm->radius_ctx);
	to_secret= sm->serv->secret;

	if (!from_secret || !to_secret)
		return;

	if (strcmp(from_secret, to_secret) == 0) {
		log_debug("[%d] same secret, no need to modify the packet\n", sm->id);
		return;
	}

	ret = radius_modify_raw_packet(is_req, sm->req, sm->req_len, from_secret,
			sm->resp, sm->resp_len, to_secret);

	log_debug("[%d] modify raw packet return=%d\n", sm->id, ret);
}


static void radproxy_remove_timeout_sm(struct radproxy_desc *proxy, struct timeval *tv_now)
{
	int i;
	struct epoll_event ee;

	for (i = 0; i < proxy->server_cnt; ++i) {
		struct radproxy_backend_server *sv = proxy->servers[i];
		if (!sv) continue;

		while (1) {
			dlist_node_t *p = dlist_get_head(&sv->sm_list);
			if (!p) break;

			struct radproxy_sm *sm = dlist_get_struct_ptr(struct radproxy_sm, active_node, p);
			int deta = radproxy_time_diff(tv_now, &sm->tv);
			int timeout = sv->timeout;

			if (sm->failover) {
				timeout = proxy->timeout;
			}

			if (deta < sv->timeout)
				break;

			sm->maxtry--;
			log_debug("[%d] timeout\n", sm->id);
			if (sm->maxtry <= 0) {
				ee.events = EPOLLIN;
				ee.data.ptr = sm;
				epoll_ctl(proxy->epfd, EPOLL_CTL_DEL, sm->fd_remote, &ee);

				if (sm->failover) {
					sm->serv->status = 1;
					sm->serv->last_check = tv_now->tv_sec;
					sm->serv->is_checking = 0;
					log_error("[%d] server [%s] down\n", sm->id, sm->serv->name);
				}

				radproxy_destroy_sm(proxy, sm);
			} else {
				log_debug("[%d] server [%s] timeout, will try again\n", sm->id, sm->serv->name);
				sm->tv = *tv_now;

				sm->state = remote_write;

				ee.events = EPOLLOUT;
				ee.data.ptr = sm;
				epoll_ctl(proxy->epfd, EPOLL_CTL_MOD, sm->fd_remote, &ee);

				dlist_remove(&sv->sm_list, &sm->active_node);
				dlist_append(&sv->sm_list, &sm->active_node);
			}
		}
	}
}

#define EVENT_SETSIZE 1024

static void* radproxy_run(struct radproxy_desc *proxy)
{
	struct epoll_event ee;
	struct epoll_event out[EVENT_SETSIZE];
	while (mainLoop) {
		int i = 0, j = 0;
		int numret = 0;
		struct timeval tv_now;
		struct radproxy_sm *sm;

		gettimeofday(&tv_now, NULL);

		radproxy_process_failover(tv_now.tv_sec, proxy);
		numret = epoll_wait(proxy->epfd, out, EVENT_SETSIZE, 1);

		if (numret < 0) {
			if (errno != EINTR)
				printf("epoll_wait error=%d\n", errno);
			radproxy_remove_timeout_sm(proxy, &tv_now);
			continue;
		}

		for (j = 0; j < numret; ++j) {
			sm = (struct radproxy_sm *)out[j].data.ptr;
			if (!sm) continue;

			switch (sm->state) {
			case local_listen:
				{
					struct radproxy_backend_server *to;
					struct radproxy_sm *new_sm;
					new_sm = radproxy_process_new_req(proxy, sm);
					if (new_sm == 0) {
						break;
					}

					to	= radproxy_apply_start(proxy, new_sm);
					if (!to) {
						radproxy_destroy_sm(proxy, new_sm);
						log_error("[%d] cannot proxy to a server\n", new_sm->id);
						break;
					}

					int fd = socket(to->addr.af, SOCK_DGRAM, 0);
					if (fd > 0) {
						new_sm->fd_remote = fd;
						memcpy(&new_sm->dest_addr, &to->addr, sizeof(to->addr));
						new_sm->maxtry = to->maxtry;

						dlist_append(&to->sm_list, &new_sm->active_node);

						ee.events = EPOLLOUT;
						ee.data.ptr = new_sm;
						epoll_ctl(proxy->epfd, EPOLL_CTL_ADD, fd, &ee);
					} else {
						log_error("[%d] open socket error", new_sm->id);
						radproxy_destroy_sm(proxy, new_sm);
					}
				}
				break;
			case remote_write:
				{
					int len;
					char ipbuf[64];
					radproxy_ipaddr_str(&sm->dest_addr, ipbuf, sizeof(ipbuf));

					log_debug("[%d] proxy to %s\n", sm->id, ipbuf);
					radproxy_modify_packet(sm, 1);
					len = radproxy_sendto(sm->fd_remote, sm->req, sm->req_len, &sm->dest_addr);
					if (len > 0) {
						log_debug("[%d] sendto %s %d bytes ok\n", sm->id, ipbuf, len);

						sm->state = remote_read;

						ee.events = EPOLLIN;
						ee.data.ptr = sm;
						epoll_ctl(proxy->epfd, EPOLL_CTL_MOD, sm->fd_remote, &ee);
						break;
					} else {
						log_error("[%d] sendto %s error, len=%d: %s\n", sm->id, ipbuf, len, strerror(errno));
						radproxy_destroy_sm(proxy, sm);
					}
				}
				break;
			case remote_read:
				{
					char buf[8192];
					struct radproxy_addr from;
					int len;

					log_debug("[%d] remote_read\n", sm->id);

					len = radproxy_recvfrom(sm->fd_remote, buf, sizeof(buf), &from);
					if (len > 0) {
						char ipbuf[64];
						log_debug("[%d] recvfrom %s %d bytes ok\n", sm->id,
							radproxy_ipaddr_str(&from, ipbuf, sizeof(ipbuf)), len);

						if (sm->serv) {
							sm->serv->last_check = tv_now.tv_sec;
							if (sm->failover) {
								log_info("[%d] server [%s] up\n", sm->id, sm->serv->name);
								sm->serv->status = 0;
								sm->serv->is_checking = 0;
								radproxy_destroy_sm(proxy, sm);
								break;
							}
						}

						sm->resp = malloc(len);
						if (sm->resp) {
							char ipbuf[64];
							radproxy_ipaddr_str(&sm->from_addr, ipbuf, sizeof(ipbuf));

							memcpy(sm->resp, buf, len);
							sm->resp_len = len;

							log_debug("[%d] repond\n", sm->id);
							radproxy_modify_packet(sm, 0);
							int len = radproxy_sendto(sm->from->fd, sm->resp, sm->resp_len, &sm->from_addr);
							if (len > 0) {
								log_debug("[%d] respond to %s %d bytes ok\n", sm->id, ipbuf , len);
								radproxy_apply_finish(proxy, sm);
								radproxy_destroy_sm(proxy, sm);
							} else {
								log_error("[%d] respond to %s error, len=%d: %s\n", sm->id, ipbuf, len, strerror(errno));
							}
							ee.events = EPOLLIN|EPOLLOUT;
							ee.data.ptr = sm;
							epoll_ctl(proxy->epfd, EPOLL_CTL_DEL, sm->fd_remote, &ee);
							break;
						}
					}
				}
				break;
			default:
				{
					log_error("[%d] wrong state\n", sm->id);
					exit(1);
				}
			}
		}
		radproxy_remove_timeout_sm(proxy, &tv_now);

	}

	radproxy_close_proxy(proxy);
	return NULL;
}


void radproxy_start(struct radproxy_data *data, int branch)
{
	if (0 != radproxy_init_server(data)) {
		fprintf(stderr, "create listen socket error\n");
		radproxy_destroy(data);
	}

	//while (branch > 1) {
	//	fork();
	//	branch--;
	//}

	struct radproxy_desc *p = data->proxys;
	while (p) {
		pthread_create(&p->thr, NULL, (void*(*)(void*))radproxy_run, p);
		p = p->next;
	}
}

void radproxy_stop(struct radproxy_data *data)
{
	struct radproxy_desc *p = data->proxys;
	while (p) {
		pthread_join(p->thr, NULL);
		p = p->next;
	}
}
