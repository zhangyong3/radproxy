#include "radproxy.h"

struct radproxy_data *radproxy_init(const char *conf_file);

int radproxy_check(struct radproxy_data *data);

void radproxy_destroy(struct radproxy_data *data);
