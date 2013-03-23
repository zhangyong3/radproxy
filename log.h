#ifndef _LOG_H_
#define _LOG_H_

#include <stdio.h>

void set_log_file(const char *filename);

void set_max_file_size(int size);

void set_log_level(int loglevel);

void log_error(const char *fmt, ...);
void log_info(const char *fmt, ...);
void log_debug(const char *fmt, ...);

void close_log_file();

#endif
