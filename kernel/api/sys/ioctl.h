#pragma once

#include <kernel/api/linux/ioctl.h>

#define TCGETS 0x5401
#define TCSETS 0x5402
#define TCSETSW 0x5403
#define TCSETSF 0x5404
#define TIOCGPGRP 0x540f
#define TIOCSPGRP 0x5410
#define TIOCGWINSZ 0x5413
#define TIOCSWINSZ 0x5414
#define TCGETS2 _IOR('T', 0x2A, struct linux_termios2)
#define TCSETS2 _IOW('T', 0x2B, struct linux_termios2)
#define TCSETSW2 _IOW('T', 0x2C, struct linux_termios2)
#define TCSETSF2 _IOW('T', 0x2D, struct linux_termios2)

struct winsize {
    unsigned short ws_row;
    unsigned short ws_col;
    unsigned short ws_xpixel;
    unsigned short ws_ypixel;
};
