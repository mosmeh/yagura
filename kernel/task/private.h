#pragma once

#include <stdnoreturn.h>

struct fs* fs_create(void);
struct files* files_create(void);
struct sighand* sighand_create(void);

noreturn void task_terminate(int signum);
