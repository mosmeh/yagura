#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>

int tcgetattr(int fd, struct termios* termios_p) {
    struct linux_termios2 linux_termios;
    if (ioctl(fd, TCGETS2, &linux_termios) < 0)
        return -1;
    *termios_p = (struct termios){
        .c_iflag = linux_termios.c_iflag,
        .c_oflag = linux_termios.c_oflag,
        .c_cflag = linux_termios.c_cflag,
        .c_lflag = linux_termios.c_lflag,
        .c_line = linux_termios.c_line,
        .c_ispeed = linux_termios.c_ispeed,
        .c_ospeed = linux_termios.c_ospeed,
    };
    memcpy(termios_p->c_cc, linux_termios.c_cc, sizeof(linux_termios.c_cc));
    return 0;
}

int tcsetattr(int fd, int optional_actions, const struct termios* termios_p) {
    int cmd;
    switch (optional_actions) {
    case TCSANOW:
        cmd = TCSETS2;
        break;
    case TCSADRAIN:
        cmd = TCSETSW2;
        break;
    case TCSAFLUSH:
        cmd = TCSETSF2;
        break;
    default:
        errno = EINVAL;
        return -1;
    }
    struct linux_termios2 linux_termios = {
        .c_iflag = termios_p->c_iflag,
        .c_oflag = termios_p->c_oflag,
        .c_cflag = termios_p->c_cflag,
        .c_lflag = termios_p->c_lflag,
        .c_line = termios_p->c_line,
        .c_ispeed = termios_p->c_ispeed,
        .c_ospeed = termios_p->c_ospeed,
    };
    memcpy(linux_termios.c_cc, termios_p->c_cc, sizeof(linux_termios.c_cc));
    return ioctl(fd, cmd, &linux_termios);
}
