#include "radproxy.h"

struct radproxy_data *radproxy_init(const char *conf_file);

void radproxy_destroy(struct radproxy_data *data);
