#pragma once

#include "forward.h"

unix_socket* unix_socket_create(void);
void unix_socket_set_backlog(unix_socket*, int backlog);
unix_socket* unix_socket_accept(unix_socket* listener);
int unix_socket_connect(file_description* connector_fd, unix_socket* listener);
