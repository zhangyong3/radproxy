#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include "cfgparse.h"
#include "radproxy.h"
#include "dlist.h"

#define MAX_ARGS 64
#define KW_LISTEN 1
#define KW_CLIENT 2

static void free_server(struct radproxy_backend_server *s)
{
	if (s) {
		if (s->name)
			free(s->name);
		if (s->secret)
			free(s->secret);
		free(s);
	}
}

static struct radproxy_backend_server *parse_server(int linenum, char *args[], int argc)
{
	int j = 0;
	struct radproxy_backend_server *s;
	char *p;
	const char *errmsg;
	if (argc < 2) {
		errmsg = "not enough paramter";
		goto error;
	}

	s = calloc(1, sizeof(*s));
	if (!s)
		return NULL;

	s->name = strdup(args[0]);
	p = (char*)strrchr(args[1], ':');
	if (!p) {
		errmsg = "no port";
		goto error;
	}

	*p++ = '\0';

	if (0 != radproxy_name2addr(args[1], &s->addr)) {
		errmsg = "server addr error";
		goto error;
	}

	s->addr.port = atoi(p);
	for (j = 2; args[j] != NULL && j < argc; j++) {
		if (strcasecmp(args[j], "state") == 0 ||
				strcasecmp(args[j], "sign") == 0 ||
					strcasecmp(args[j], "nostate") == 0 ) {
			if (strcasecmp(args[j], "state") == 0) {
				s->option |= OPTION_STATE;
			} else if (strcasecmp(args[j], "nostate") == 0) {
				s->option |= OPTION_NO_STATE;
			} else if (strcasecmp(args[j], "sign") == 0) {
				s->option |= OPTION_SIGN;
			} else {
				printf("unknow keyword '%s' in server\n", args[j]);
			}

			continue;
		}

		if (argc-j <2) {
			errmsg = "need more paramter";
			goto error;
		}

		if (strcasecmp(args[j], "weight") == 0) {
			s->weight = atoi(args[j+1]);
			if (s->weight < 0) {
				errmsg = "weight cannot be negative";
				goto error;
			}
		} else if (strcasecmp(args[j], "timeout") == 0) {
			s->timeout = atoi(args[j+1]);
		} else if (strcasecmp(args[j], "try") == 0) {
			s->maxtry = atoi(args[j+1]);
				errmsg = "'try' must be positive";
		} else if (strcasecmp(args[j], "secret") == 0) {
			s->secret = strdup(args[j+1]);
		} else {
			printf("unknow keyword '%s' in server\n", args[j]);
			goto error;
		}

		j++;
	}

	if (s->timeout <=0) {
		s->timeout = 3000;
		printf("'timeout' is not positive, reset to 3000\n");
	}

	if (s->maxtry <= 0) {
		s->maxtry = 2;
		printf("'try' is not positive, reset to 2\n");
	}

	if (s->weight <= 0) {
		s->weight = 1;
		printf("'weight' is not positive, reset to 1\n");
	}

	if (s->addr.port <= 0) {
		errmsg = "port number error";
		goto error;
	} else if (s->name == NULL) {
		errmsg = "server need a name";
		goto error;
	} else if (s->secret == NULL) {
		errmsg = "server need a secret";
		goto error;
	}

	return s;

error:
	if (errmsg)
		printf("line %d: %s\n", linenum, errmsg);
	free_server(s);
	return NULL;
}

static struct addr_segment *parse_addr_segment(int linenum, char *p)
{
	struct addr_segment *s;
	struct radproxy_addr a;
	char *errmsg = NULL;

	s = calloc(1, sizeof(*s));
	if (!s)
		return NULL;

	if (radproxy_name2addr(p, &a) == 0) {
		radproxy_ipaddr2segment(s, &a);
	} else {
		char delim;
		int loop;
		int i = 0;
		if (strchr(p, ':') != NULL) {
			delim = ':';
			loop = 16;
		} else if (strchr(p, '.') != NULL) {
			delim = '.';
			loop = 4;
			s->ipv4 = 1;
		} else {
			errmsg = "bad client addr format";
			goto error;
		}

		while (p && *p) {
			--loop;
			char *d;
			char *q = strchr(p, delim);
			if (q) {
				*q = '\0';
			}

			d = strchr(p, '-');
			if (d) {
				*d++ = '\0';
				s->seg[i].start = strtol(p, NULL, s->ipv4?10:16);
				s->seg[i].end = strtol(d, NULL, s->ipv4?10:16);
			} else {
				s->seg[i].start = s->seg[i].end = strtol(p, NULL, s->ipv4?10:16);
			}
			i++;

			if (!q)
				break;

			p = q+1;
		}

		if (loop != 0) {
			errmsg = "incorrect ip segment";
			goto error;
		}
	}

	return s;

error:
	if (errmsg)
		printf("line %d: %s\n", linenum, errmsg);

	if (s)
		free(s);
	return NULL;
}

void free_client(struct radproxy_client *c)
{
	if (c) {
		if (c->secret)
			free(c->secret);
		free(c);
	}
}

static struct radproxy_client *parse_client(int linenum, char *args[], int argc)
{
	char *errmsg = NULL;
	struct radproxy_client *c;
	if (argc != 2) {
		errmsg = "client parameter error";
		goto error;
	}

	c = calloc(1, sizeof(*c));
	if (!c)
		goto error;

	c->addr_seg = parse_addr_segment(linenum, args[0]);
	if (!c->addr_seg) {
		errmsg = "client ip error";
		goto error;
	}

	c->secret = strdup(args[1]);
	if (!c->secret || strlen(c->secret) == 0) {
		errmsg = "no client secret";
		goto error;
	}
	/*
	printf("%d.%d.%d.%d -> %s\n", c->addr_seg->seg[0].start,
		c->addr_seg->seg[1].start,
		c->addr_seg->seg[2].start,
		c->addr_seg->seg[3].start, c->secret);
	*/
	return c;

error:
	if (errmsg)
		printf("line %d: %s\n", linenum, errmsg);
	free_client(c);
	return NULL;
}

static void free_proxy(struct radproxy_desc *p)
{
	int i = 0;
	if (p) {
		for (i = 0;i < p->server_cnt; ++i) {
			struct radproxy_backend_server *s = p->servers[i];
			if (!s) continue;

			free_server(s);
		}

		free(p);
	}
}

static int parse(struct radproxy_data *cfg, int linenum, char *args[], int argc)
{
	char *errmsg = NULL;
	static int kwtype = 0;

	if (argc <= 0) {
		printf("line %d: no parameter\n", linenum);
		return -1;
	}

	if (strcasecmp(args[0], "listen") == 0) {
		kwtype = KW_LISTEN;
	} else if (strcasecmp(args[0], "client") == 0) {
		kwtype = KW_CLIENT;
		return 0;
	}
	/*else {
		printf("line %d: unknown keyword '%s'", linenum, args[0]);
		return -2;
	}*/

	switch(kwtype)
	{
	case KW_CLIENT:
		{
			struct radproxy_client *c = parse_client(linenum, args, argc);
			if (!c)
				goto error;
			if (!cfg->clients) {
				cfg->clients = c;
			} else {
				struct radproxy_client *p = cfg->clients;
				while (p && p->next) p=p->next;
				p->next = c;
			}
		}
		break;
	case KW_LISTEN:
		{
			struct radproxy_desc *p;
			if (strcasecmp(args[0], "listen") == 0) {
				if (argc != 2) {
					errmsg = "a port number needed after keyword listen";
					goto error;
				}

				p = calloc(1, sizeof(*p));
				if (!p)
					goto error;

				dlist_init(&p->server_list);
				p->port = atoi(args[1]);
				if (p->port <= 0) {
					errmsg = "invalid port number";
					goto error;
				}

				if (cfg->proxys) {
					struct radproxy_desc *q = cfg->proxys;
					while (q && q->next) q = q->next;
					q->next = p;
				} else {
					cfg->proxys = p;
				}
				break;
			}

			p = cfg->proxys;
			while (p &&p->next) p=p->next;
			if (!p) {
				errmsg = "go hell";
				goto error;
			}
			if (strcasecmp(args[0], "mode") == 0) {
				if (argc != 2) {
					goto error;
				}

				if (strcasecmp(args[1], "radius") == 0) {
					p->mode = mode_radius;
				} else if (strcasecmp(args[1], "udp") == 0) {
					p->mode = mode_udp;
				} else {
					errmsg = "unknown mode";
					goto error;
				}
			} else if (strcasecmp(args[0], "option") == 0) {
				if (argc < 2) {
					errmsg = "not enough parameter after keyword option";
					goto error;
				}

				if (strcasecmp(args[1], "state") == 0) {
					p->option |= OPTION_STATE;
					if (argc != 3) {
						errmsg = "a state timeout number needed after 'state'";
						goto error;
					}
					p->state_timeout = atoi(args[2]);
					if (p->state_timeout < 0) {
						p->state_timeout = 60;
						printf("invalid state timeout value '%d', reset to 60s\n", p->state_timeout);
					}
					p->ht_state = fr_hash_table_create(hash_state, hash_state_cmp, NULL);
				} else if (strcasecmp(args[1], "roundrobin") == 0) {
					p->option |= OPTION_ROUND_ROBIN;
				} else if (strcasecmp(args[1], "source") == 0) {
					p->option |= OPTION_SOURCE;
				} else if (strcasecmp(args[1], "sign") == 0) {
					p->option |= OPTION_SIGN;
				} else if (strcasecmp(args[1], "packchk") == 0) {
					p->option |= OPTION_PACK_CHECK;
				} else if (strcasecmp(args[1], "failover") == 0) {
					p->option |= OPTION_FAILOVER;
					if (argc != 5) {
						errmsg = "parameter 'interv'(s) 'timeout'(ms) 'maxtry' needed after keyword 'failover'";
						goto error;
					}

					p->interv = atoi(args[2]);
					p->timeout = atoi(args[3]);
					p->maxtry = atoi(args[4]);

					if (p->interv <= 0)
						p->interv = 10;
					if (p->timeout <= 0)
						p->timeout = 3000;
					if (p->maxtry <= 0)
						p->maxtry = 3;
				} else {
					printf("line %d: unknown keyword '%s'\n", linenum, args[1]);
					goto error;
				}
			} else if (strcasecmp(args[0], "server") == 0) {
				struct radproxy_backend_server *s = parse_server(linenum, args+1, argc-1);
				if (s) {
					dlist_append(&p->server_list, &s->node);
					/*
					struct radproxy_backend_server **q = realloc(p->servers, (p->server_cnt+1)*sizeof(struct radproxy_back_server*));
					if (q) {
						q[p->server_cnt] = s;
						p->servers = q;
						p->server_cnt += 1;
					}
					*/
				} else {
					goto error;
				}
			} else if (strcasecmp(args[0], "name") == 0) {
				if (argc >= 2) {
					if (p->name)
						free(p->name);
					p->name = strdup(args[1]);
				}
			}

		}
		break;
	}

	return 0;

error:
	if (errmsg)
	printf("line %d: %s\n", linenum, errmsg);
	return 1;
}


struct radproxy_data *radproxy_init(const char *file)
{
	struct radproxy_data *data;

	FILE *fp;
	char line[1024*4];
	char *args[MAX_ARGS+1];
	char *pos;
	char *end;
	int ret = 0;
	int linenum = 0;

   	fp= fopen(file, "r");
	if (!fp) {
		printf("cannot open config file '%s'\n", file);
		return NULL;
	}

	data = calloc(1, sizeof(*data));
	if (!data) {
		fclose(fp);
		return NULL;
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		int i = 0;
		linenum++;
		pos = line;

		memset(args, 0, sizeof(args));
		while (*pos && isspace(*pos)) pos++;
		if (!*pos ||  *pos == '#' || *pos == ';') continue;

		for (i = 0; *pos && i < MAX_ARGS; ++i) {
			args[i] = pos;
			while (*pos && !isspace(*pos)) pos++;

			if (!*pos)
				break;

			*pos++ = '\0';
			while (*pos && isspace(*pos)) pos++;
		}

		if (parse(data, linenum, args, i) != 0) {
			goto error;
		}
	}

	if (radproxy_check(data) != 0)
		goto error;

	fclose(fp);
	return data;

error:
	fclose(fp);
	if (data) {
		radproxy_destroy(data);
	}

	return NULL;
}



void radproxy_destroy(struct radproxy_data *data)
{
	if (data) {
		struct radproxy_client *c = data->clients;
		struct radproxy_desc *p = data->proxys;

		while (c) {
			struct radproxy_client *q =c;
			c = c->next;
			free_client(q);
		}

		while (p) {
			struct radproxy_desc *q =p;
			p = p->next;
			free_proxy(q);
		}

		free(data);
	}

}

int radproxy_check(struct radproxy_data *data)
{
	if (data) {
		struct radproxy_desc *p = data->proxys;
		while (p) {
			if (!p->name) {
				printf("proxy name required for port %d\n", p->port);
				return 1;
			}

			if (dlist_size(&p->server_list) <= 0) {
				printf("at least one server should be specified in %s\n", p->name);
				return 2;
			}

			if (p->option & OPTION_ROUND_ROBIN &&
					p->option & OPTION_SOURCE) {
				printf("round robin and source cannot be combined in %s\n", p->name);
				return 3;
			}

			if (!(p->option & OPTION_ROUND_ROBIN) &&
					!(p->option & OPTION_SOURCE)) {
				p->option |= OPTION_ROUND_ROBIN;
				//printf("use round robin\n");
			}

			p = p->next;
		}

	}
	return 0;
}
