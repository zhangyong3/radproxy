#ifndef RADPROXY_H
#define RADPROXY_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <pthread.h>
#include "common.h"
#include "hash.h"

#define OPTION_ROUND_ROBIN 1
#define OPTION_SOURCE      2
#define OPTION_SIGN        4
#define OPTION_PACK_CHECK  8
#define OPTION_STATE       16
#define OPTION_NO_STATE    32
#define OPTION_FAILOVER    64

typedef enum {mode_udp, mode_radius} proxy_mode_t;

struct radproxy_back_server
{
	char *name;
	struct radproxy_addr addr;
	int maxtry;
	int timeout;
	unsigned int option;
	char *secret;
	int weight;
	int status;
	time_t last_check;
	int is_checking;
};

struct radproxy_listen_interface;
struct radproxy_desc
{
	char *name;
	int epfd;
	struct radproxy_listen_interface *listens;
	int listen_size;

	int port;
	proxy_mode_t mode;
	unsigned int option;
	int state_timeout;

	int server_cnt;
	int cur;
	struct radproxy_back_server **servers;
	fr_hash_table_t *ht_state;

	int interv;
	int maxtry;
	int timeout;

	struct radproxy_sm **sms;
	int size_sm;
	struct radproxy_sm *freesms;

	unsigned int sm_id;

	struct radproxy_desc *next;
	pthread_t thr;
	struct radproxy_client *clients;
};

struct radproxy_client
{
	char *secret;
	struct addr_segment *addr_seg;
	struct radproxy_client *next;
};

struct radius_state_node
{
	void *data;
	int datalen;
	time_t create_tm;
	struct radproxy_back_server *serv;
};


struct radproxy_listen_interface
{
	int fd;
	struct radproxy_addr addr;
};


struct radproxy_sm
{
	unsigned int id;
	struct radproxy_addr from_addr;
	struct radproxy_addr dest_addr;
	struct radproxy_addr local_addr;

	struct radproxy_listen_interface *from;

	int fd_remote;

	unsigned char *req;
	int req_len;
	unsigned char *resp;
	int resp_len;

	int index;
	struct timeval tv;
	int timeout;
	int maxtry;
	enum {local_listen, process_local, remote_write, remote_read, respond, timeout, finish, error} state;

	struct radproxy_desc *p;
	void *radius_ctx;
	struct radproxy_back_server *serv;
	int failover;

	struct radproxy_sm *next;
};



struct radproxy_data
{
	struct radproxy_client *clients;
	struct radproxy_desc *proxys;
};

void radproxy_start(struct radproxy_data *data, int branch);

void radproxy_stop(struct radproxy_data *data);

#endif

