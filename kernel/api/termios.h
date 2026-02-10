#pragma once

#define LINUX_NCCS 19

typedef unsigned char cc_t;
typedef unsigned int speed_t;
typedef unsigned int tcflag_t;

struct linux_termios {
    tcflag_t c_iflag;      // input mode flags
    tcflag_t c_oflag;      // output mode flags
    tcflag_t c_cflag;      // control mode flags
    tcflag_t c_lflag;      // local mode flags
    cc_t c_line;           // line discipline
    cc_t c_cc[LINUX_NCCS]; // control characters
};

struct linux_termios2 {
    tcflag_t c_iflag;      // input mode flags
    tcflag_t c_oflag;      // output mode flags
    tcflag_t c_cflag;      // control mode flags
    tcflag_t c_lflag;      // local mode flags
    cc_t c_line;           // line discipline
    cc_t c_cc[LINUX_NCCS]; // control characters
    speed_t c_ispeed;      // input speed
    speed_t c_ospeed;      // output speed
};

// c_iflag bits
// Ignore break condition.
#define IGNBRK 0000001
// Signal interrupt on break.
#define BRKINT 0000002
// Ignore characters with parity errors.
#define IGNPAR 0000004
// Mark parity and framing errors.
#define PARMRK 0000010
// Enable input parity check.
#define INPCK 0000020
// Strip 8th bit off characters.
#define ISTRIP 0000040
// Map NL to CR on input.
#define INLCR 0000100
// Ignore CR.
#define IGNCR 0000200
// Map CR to NL on input.
#define ICRNL 0000400
// Map uppercase characters to lowercase on input (not in POSIX).
#define IUCLC 0001000
// Enable start/stop output control.
#define IXON 0002000
// Enable any character to restart output.
#define IXANY 0004000
// Enable start/stop input control.
#define IXOFF 0010000
// Ring bell when input queue is full (not in POSIX).
#define IMAXBEL 0020000
// Input is UTF8 (not in POSIX).
#define IUTF8 0040000

// c_oflag bits
// Post-process output.
#define OPOST 0000001
// Map lowercase characters to uppercase on output. (not in POSIX).
#define OLCUC 0000002
// Map NL to CR-NL on output.
#define ONLCR 0000004
// Map CR to NL on output.
#define OCRNL 0000010
// No CR output at column 0.
#define ONOCR 0000020
// NL performs CR function.
#define ONLRET 0000040
// Use fill characters for delay.
#define OFILL 0000100
// Fill is DEL.
#define OFDEL 0000200

// c_cflag bits.
#define CSIZE 0000060
#define CS5 0000000
#define CS6 0000020
#define CS7 0000040
#define CS8 0000060
#define CSTOPB 0000100
#define CREAD 0000200
#define PARENB 0000400
#define PARODD 0001000
#define HUPCL 0002000
#define CLOCAL 0004000

// c_cflag bit meaning
#define B0 0000000 /* hang up */
#define B50 0000001
#define B75 0000002
#define B110 0000003
#define B134 0000004
#define B150 0000005
#define B200 0000006
#define B300 0000007
#define B600 0000010
#define B1200 0000011
#define B1800 0000012
#define B2400 0000013
#define B4800 0000014
#define B9600 0000015
#define B19200 0000016
#define B38400 0000017

// c_lflag bits
// Enable signals.
#define ISIG 0000001
// Canonical input (erase and kill processing).
#define ICANON 0000002
// Enable echo.
#define ECHO 0000010
// Echo erase character as error-correcting backspace.
#define ECHOE 0000020
// Echo KILL.
#define ECHOK 0000040
// Echo NL.
#define ECHONL 0000100
// Disable flush after interrupt or quit.
#define NOFLSH 0000200
// Send SIGTTOU for background output.
#define TOSTOP 0000400
// Enable implementation-defined input processing.
#define IEXTEN 0100000

// c_cc characters
#define VINTR 0
#define VQUIT 1
#define VERASE 2
#define VKILL 3
#define VEOF 4
#define VTIME 5
#define VMIN 6
#define VSWTC 7
#define VSTART 8
#define VSTOP 9
#define VSUSP 10
#define VEOL 11
#define VREPRINT 12
#define VDISCARD 13
#define VWERASE 14
#define VLNEXT 15
#define VEOL2 16

#define TTYDEF_IFLAG ICRNL
#define TTYDEF_OFLAG (OPOST | ONLCR)
#define TTYDEF_LFLAG (ECHO | ICANON | ISIG | ECHOE | ECHOK | ECHONL)
#define TTYDEF_CFLAG CS8
#define TTYDEF_SPEED B9600

#define CTRL(x) ((x) & 0x1f)
#define CEOF CTRL('d')
#define CEOL '\0'
#define CERASE 0177
#define CINTR CTRL('c')
#define CSTATUS '\0'
#define CKILL CTRL('u')
#define CMIN 1
#define CSWTC 0
#define CQUIT 034
#define CSUSP CTRL('z')
#define CTIME 0
#define CDSUSP CTRL('y')
#define CSTART CTRL('q')
#define CSTOP CTRL('s')
#define CLNEXT CTRL('v')
#define CDISCARD CTRL('o')
#define CWERASE CTRL('w')
#define CREPRINT CTRL('r')
#define CEOL2 CEOL

#define CEOT CEOF
#define CBRK CEOL
#define CRPRNT CREPRINT
#define CFLUSH CDISCARD

#define TCSANOW 0
#define TCSADRAIN 1
#define TCSAFLUSH 2
