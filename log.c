#include "log.h"
#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>


#define LOGLEVEL_ERROR 0
#define LOGLEVEL_INFO 1
#define LOGLEVEL_DEBUG 2

static int loglevel = 1;
static FILE *output = NULL;
static const char *logfile = NULL;
static int filesize = 0;


void set_log_file(const char *filename)
{
	if (filename != NULL) {
		logfile = filename;
		if (output)
			fclose(output);
		output =fopen(filename, "a+");
	}

	if (!output)
		output = stdout;
}

void close_log_file()
{
	if (output)
		fclose(output);
}

void set_max_file_size(int size)
{
	filesize = size;
}

void set_log_level(int level)
{
	loglevel = level;
}


static void writelog(const char *tag, const char *fmt, va_list *ap)
{
	struct timeval tv;
	struct tm t;
	static unsigned int line =0;

	gettimeofday(&tv, NULL);
	localtime_r(&tv.tv_sec, &t);

	if (logfile && filesize > 0 && (ftell(output) > filesize)) {
		char newfile[256];
		sprintf(newfile, "%s.%04d%02d%02d%02d%02d%02d",
				logfile, t.tm_year+1900, t.tm_mon+1,
				t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec);

		if (access(newfile, F_OK) != 0) {
			rename(logfile, newfile);
			set_log_file(logfile);
		}
	}

	fprintf(output, "%04d/%02d/%02d %02d:%02d:%02d.%06d <%s> ", t.tm_year+1900, t.tm_mon+1, t.tm_mday,
		t.tm_hour, t.tm_min, t.tm_sec, tv.tv_usec, tag);


	vfprintf(output, fmt, *ap);
	if (line++ % 10 == 0)
		fflush(output);
}


void log_error(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	writelog("ERROR", fmt, &ap);
	va_end(ap);
}

void log_info(const char *fmt, ...)
{
	va_list ap;

	if (loglevel < LOGLEVEL_INFO)
		return;

	va_start(ap, fmt);
	writelog("INFO ", fmt, &ap);
	va_end(ap);
}

void log_debug(const char *fmt, ...)
{
	va_list ap;

	if (loglevel < LOGLEVEL_DEBUG)
		return;

	va_start(ap, fmt);
	writelog("DEUBG", fmt, &ap);
	va_end(ap);
}

