#pragma once

void task_fs_init(void);
void task_signal_init(void);

struct fs_env* fs_env_create(void);
struct fd_table* fd_table_create(void);
struct sighand* sighand_create(void);

_Noreturn void task_terminate(int signum);
