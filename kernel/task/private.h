#pragma once

#include <stdnoreturn.h>

void task_fs_init(void);
void task_signal_init(void);

struct fs* fs_create(void);
struct files* files_create(void);
struct sighand* sighand_create(void);

noreturn void task_terminate(int signum);
