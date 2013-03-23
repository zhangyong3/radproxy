#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include "radproxy.h"
#include "cfgparse.h"

int mainLoop = 1;
static void handle_term(int signo)
{
	if (signo == SIGINT) {
		log_info("got signal SIGINT, begin to exit\n");
		mainLoop = 0;
	}
}

static void show_usage()
{
	printf ("-------------------------------------\n");
	printf ("Copyrights completely reserved by zhangyong309@163.com\n");
	printf ("radproxy v0.1\n");
	printf ("used to loadbalance radius servers\n");
	printf ("-------------------------------------\n");
	printf ("Usage: radproxy -h -x -l logfile -f conf -b branch -d\n");
	printf (" -f config file\n");
	printf (" -x loglevel: INFO\n");
	printf (" -xx loglevel: DEBUG\n");
	printf (" -b branch\n");
	printf (" -l logfile\n");
	printf (" -h show this help\n");
	printf (" -d deamon\n");
	exit(0);
}


int main(int argc, char *argv[])
{
	struct radproxy_desc_config *cfg;
	char *cfg_file = "./radproxy.conf";
	char *logfile = NULL;
	struct radproxy_data *data;
	int loglevel = 1;
	int branch;
	int deamon = 0;

	int xx=0;
	if (argc > 1) {
		int opt;
		while ((opt = getopt(argc, argv, "l:f:b:xdvh")) > 0) {
			switch(opt) {
			case 'f':
				cfg_file = optarg;
				break;
			case 'b':
				branch = atoi(optarg);
				break;
			case 'x':
				xx++;
				break;
			case 'l':
				logfile = optarg;
				break;
			case 'd':
				deamon = 1;
				break;
			default:
				show_usage();
				break;
			}
		}
	}
	if (xx != 0)
		loglevel=xx;

	if (deamon) {
		if (fork() > 0)
			exit(0);
	}

	signal(SIGINT, handle_term);
	set_log_level(loglevel);
	set_log_file(logfile);

	data = radproxy_init(cfg_file);
	if (!data)
		exit(1);

	radproxy_start(data, branch);

	radproxy_stop(data);

	radproxy_destroy(data);

	log_info("radproxy exited\n");
	close_log_file();
	exit(0);
}
