#include <common/extra.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

struct flag {
    const char* name;
    tcflag_t value;
    tcflag_t mask;
};

static const struct flag iflags[] = {
    {"ignbrk", IGNBRK, IGNBRK}, {"brkint", BRKINT, BRKINT},
    {"ignpar", IGNPAR, IGNPAR}, {"parmer", PARMRK, PARMRK},
    {"inpck", INPCK, INPCK},    {"istrip", ISTRIP, ISTRIP},
    {"inlcr", INLCR, INLCR},    {"igncr", IGNCR, IGNCR},
    {"icrnl", ICRNL, ICRNL},    {"iuclc", IUCLC, IUCLC},
    {"ixon", IXON, IXON},       {"ixany", IXANY, IXANY},
    {"ixoff", IXOFF, IXOFF},    {"imaxbel", IMAXBEL, IMAXBEL},
    {"iutf8", IUTF8, IUTF8},
};

static const struct flag oflags[] = {
    {"opost", OPOST, OPOST}, {"olcuc", OLCUC, OPOST},
    {"onlcr", ONLCR, ONLCR}, {"onlret", ONLRET, ONLRET},
    {"ofill", OFILL, OFILL}, {"ofdel", OFDEL, OFDEL},
};

static const struct flag cflags[] = {
    {"cs5", CS5, CSIZE},        {"cs6", CS6, CSIZE},
    {"cs7", CS7, CSIZE},        {"cs8", CS8, CSIZE},
    {"cstopb", CSTOPB, CSTOPB}, {"cread", CREAD, CREAD},
    {"parenb", PARENB, PARENB}, {"parodd", PARODD, PARODD},
    {"hupcl", HUPCL, HUPCL},    {"clocal", CLOCAL, CLOCAL},
};

static const struct flag lflags[] = {
    {"isig", ISIG, ISIG},       {"icanon", ICANON, ICANON},
    {"echo", ECHO, ECHO},       {"echoe", ECHOE, ECHOE},
    {"echok", ECHOK, ECHOK},    {"echonl", ECHONL, ECHONL},
    {"noflsh", NOFLSH, NOFLSH}, {"tostop", TOSTOP, TOSTOP},
    {"iexten", IEXTEN, IEXTEN},
};

struct baud {
    speed_t speed;
    unsigned value;
};

static const struct baud bauds[] = {
    {B0, 0},       {B50, 50},     {B75, 75},       {B110, 110},
    {B134, 134},   {B150, 150},   {B200, 200},     {B300, 300},
    {B600, 600},   {B1200, 1200}, {B1800, 1800},   {B2400, 2400},
    {B4800, 4800}, {B9600, 9600}, {B19200, 19200}, {B38400, 38400},
};

struct cc {
    const char* name;
    unsigned index;
};

static const struct cc ccs[] = {
    {"intr", VINTR},     {"quit", VQUIT},       {"erase", VERASE},
    {"kill", VKILL},     {"eof", VEOF},         {"swtc", VSWTC},
    {"start", VSTART},   {"stop", VSTOP},       {"susp", VSUSP},
    {"eol", VEOL},       {"reprint", VREPRINT}, {"discard", VDISCARD},
    {"werase", VWERASE}, {"lnext", VLNEXT},     {"eol2", VEOL2},
};

static unsigned baud_to_value(speed_t baud) {
    for (size_t i = 0; i < ARRAY_SIZE(bauds); ++i) {
        if (baud == bauds[i].speed)
            return bauds[i].value;
    }
    return 0;
}

static speed_t parse_baud(const char* s) {
    if (!s) {
        dprintf(STDERR_FILENO, "Missing baud rate\n");
        exit(EXIT_FAILURE);
    }
    speed_t baud = atoi(s);
    for (size_t i = 0; i < ARRAY_SIZE(bauds); ++i) {
        if (baud == bauds[i].value)
            return bauds[i].speed;
    }
    dprintf(STDERR_FILENO, "Invalid baud rate: %s\n", s);
    exit(EXIT_FAILURE);
}

static void print_flags(const struct flag* flags, size_t num_flags,
                        tcflag_t value, tcflag_t default_value) {
    bool printed = false;
    for (size_t i = 0; i < num_flags; ++i) {
        if ((value & flags[i].mask) == (default_value & flags[i].mask))
            continue;
        bool set = (value & flags[i].mask) == flags[i].value;
        if (!set)
            printf("-");
        printf("%s ", flags[i].name);
        printed = true;
    }
    if (printed)
        putchar('\n');
}

static bool apply_flag(tcflag_t* dest, const char* name,
                       const struct flag* flag, bool set) {
    if (strcmp(flag->name, name) != 0)
        return false;

    *dest &= ~flag->mask;
    if (set)
        *dest |= flag->value;
    return true;
}

static cc_t parse_cc(const char* s) {
    if (!s) {
        dprintf(STDERR_FILENO, "Missing control character\n");
        exit(EXIT_FAILURE);
    }
    if (s[0] == '^' && s[1] != '\0' && s[2] == '\0')
        return toupper(s[1]) - 0x40;
    dprintf(STDERR_FILENO, "Invalid control character: %s\n", s);
    exit(EXIT_FAILURE);
}

int main(int argc, char* const argv[]) {
    struct termios termios;
    if (tcgetattr(STDIN_FILENO, &termios) < 0) {
        perror("tcgetattr");
        return EXIT_FAILURE;
    }
    struct winsize winsize;
    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &winsize) < 0) {
        perror("ioctl");
        return EXIT_FAILURE;
    }

    if (argc < 2) {
        printf("speed %u baud; rows %u; columns %u; line = %u;\n",
               baud_to_value(termios.c_ispeed), winsize.ws_row, winsize.ws_col,
               termios.c_line);

        for (size_t i = 0; i < ARRAY_SIZE(ccs); ++i) {
            printf("%s = ", ccs[i].name);
            cc_t cc = termios.c_cc[ccs[i].index];
            if (cc == 0x7f)
                printf("^?; ");
            else if (cc)
                printf("^%c; ", cc + 0x40);
            else
                printf("<undef>; ");
        }
        putchar('\n');

        print_flags(cflags, ARRAY_SIZE(cflags), termios.c_cflag, TTYDEF_CFLAG);
        print_flags(oflags, ARRAY_SIZE(oflags), termios.c_oflag, TTYDEF_OFLAG);
        print_flags(iflags, ARRAY_SIZE(iflags), termios.c_iflag, TTYDEF_IFLAG);
        print_flags(lflags, ARRAY_SIZE(lflags), termios.c_lflag, TTYDEF_LFLAG);

        return EXIT_SUCCESS;
    }

    char* const* arg = argv + 1;
    while (*arg) {
        for (size_t i = 0; i < ARRAY_SIZE(ccs); ++i) {
            if (!strcmp(*arg, ccs[i].name)) {
                termios.c_cc[ccs[i].index] = parse_cc(*++arg);
                goto next;
            }
        }

        if (isdigit((*arg)[0])) {
            termios.c_ispeed = termios.c_ospeed = parse_baud(*arg);
            goto next;
        }
        if (!strcmp(*arg, "ispeed")) {
            termios.c_ispeed = parse_baud(*++arg);
            goto next;
        }
        if (!strcmp(*arg, "ospeed")) {
            termios.c_ospeed = parse_baud(*++arg);
            goto next;
        }

        if (!strcmp(*arg, "columns") || !strcmp(*arg, "cols")) {
            winsize.ws_col = atoi(*++arg);
            goto next;
        }
        if (!strcmp(*arg, "rows")) {
            winsize.ws_row = atoi(*++arg);
            goto next;
        }

        if (!strcmp(*arg, "evenp") || !strcmp(*arg, "parity")) {
            termios.c_cflag &= ~(CSIZE | PARODD);
            termios.c_cflag |= CS7 | PARENB;
            goto next;
        }
        if (!strcmp(*arg, "oddp")) {
            termios.c_cflag &= ~CSIZE;
            termios.c_cflag |= CS7 | PARENB | PARODD;
        }
        if (!strcmp(*arg, "-parity") || !strcmp(*arg, "-evenp") ||
            !strcmp(*arg, "-oddp")) {
            termios.c_cflag &= ~(PARENB | CSIZE);
            termios.c_cflag |= CS8;
            goto next;
        }

        if (!strcmp(*arg, "raw")) {
            termios.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR |
                                 IGNCR | ICRNL | IXON);
            termios.c_lflag &= ~OPOST;
            termios.c_cflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
            termios.c_cflag |= CS8;
            goto next;
        }
        if (!strcmp(*arg, "ek")) {
            termios.c_cc[VERASE] = CERASE;
            termios.c_cc[VKILL] = CKILL;
            goto next;
        }
        if (!strcmp(*arg, "sane")) {
            termios.c_iflag = TTYDEF_IFLAG;
            termios.c_oflag = TTYDEF_OFLAG;
            termios.c_cflag = TTYDEF_CFLAG;
            termios.c_lflag = TTYDEF_LFLAG;
            termios.c_ispeed = termios.c_ospeed = TTYDEF_SPEED;
            for (size_t i = 0; i < NCCS; ++i)
                termios.c_cc[i] = ttydefchars[i];
            goto next;
        }

        char* p = *arg;
        bool set = true;
        if (p[0] == '-') {
            set = false;
            ++p;
        }

        if (!strcmp(p, "nl")) {
            if (set) {
                termios.c_iflag &= ~ICRNL;
            } else {
                termios.c_iflag &= ~(INLCR | IGNCR);
                termios.c_iflag |= ICRNL;
            }
            goto next;
        }

        for (size_t i = 0; i < ARRAY_SIZE(iflags); ++i) {
            if (apply_flag(&termios.c_iflag, p, &iflags[i], set))
                goto next;
        }
        for (size_t i = 0; i < ARRAY_SIZE(oflags); ++i) {
            if (apply_flag(&termios.c_oflag, p, &oflags[i], set))
                goto next;
        }
        for (size_t i = 0; i < ARRAY_SIZE(cflags); ++i) {
            if (apply_flag(&termios.c_cflag, p, &cflags[i], set))
                goto next;
        }
        for (size_t i = 0; i < ARRAY_SIZE(lflags); ++i) {
            if (apply_flag(&termios.c_lflag, p, &lflags[i], set))
                goto next;
        }

        dprintf(STDERR_FILENO, "Invalid argument %s\n", *arg);
        return EXIT_FAILURE;

    next:
        ++arg;
    }

    if (tcsetattr(STDIN_FILENO, TCSADRAIN, &termios) < 0) {
        perror("tcsetattr");
        return EXIT_FAILURE;
    }
    if (ioctl(STDIN_FILENO, TIOCSWINSZ, &winsize) < 0) {
        perror("ioctl");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
