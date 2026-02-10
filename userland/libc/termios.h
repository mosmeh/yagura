#pragma once

#include <kernel/api/termios.h>

#define NCCS 32

struct termios {
    tcflag_t c_iflag; // input mode flags
    tcflag_t c_oflag; // output mode flags
    tcflag_t c_cflag; // control mode flags
    tcflag_t c_lflag; // local mode flags
    cc_t c_line;      // line discipline
    cc_t c_cc[NCCS];  // control characters
    speed_t c_ispeed; // input speed
    speed_t c_ospeed; // output speed
};

static const cc_t ttydefchars[NCCS] = {
    [VINTR] = CINTR,       [VQUIT] = CQUIT,       [VERASE] = CERASE,
    [VKILL] = CKILL,       [VEOF] = CEOF,         [VTIME] = CTIME,
    [VMIN] = CMIN,         [VSWTC] = CSWTC,       [VSTART] = CSTART,
    [VSTOP] = CSTOP,       [VSUSP] = CSUSP,       [VEOL] = CEOL,
    [VREPRINT] = CREPRINT, [VDISCARD] = CDISCARD, [VWERASE] = CWERASE,
    [VLNEXT] = CLNEXT,     [VEOL2] = CEOL2,
};

int tcgetattr(int fd, struct termios* termios_p);
int tcsetattr(int fd, int optional_actions, const struct termios* termios_p);
