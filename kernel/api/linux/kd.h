#pragma once

#define KDGKBTYPE 0x4b33 // get keyboard type
#define KB_84 0x01
#define KB_101 0x02
#define KB_OTHER 0x03

#define KDGKBMODE 0x4b44 // gets current keyboard mode
#define KDSKBMODE 0x4b45 // sets current keyboard mode
#define K_RAW 0x00
#define K_XLATE 0x01
#define K_MEDIUMRAW 0x02

struct kbdiacruc {
    unsigned int diacr, base, result;
};
