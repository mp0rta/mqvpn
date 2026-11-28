// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* The real listen(), reachable from a TU that remaps the name. */
#include <sys/socket.h>

int
real_listen(int fd, int backlog)
{
    return listen(fd, backlog);
}
