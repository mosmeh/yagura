#include <kernel/api/signum.h>
#include <kernel/process.h>

void tty_maybe_send_signal(pid_t pgid, char ch) {
    switch (ch) {
    case 'C' - '@':
        process_send_signal_to_group(pgid, SIGINT);
        break;
    case '\\' - '@':
        process_send_signal_to_group(pgid, SIGQUIT);
        break;
    }
}
