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

struct kbentry {
    unsigned char kb_table;
    unsigned char kb_index;
    unsigned short kb_value;
};

#define KDGKBENT 0x4b46 // gets one entry in translation table
#define KDSKBENT 0x4b47 // sets one entry in translation table

struct kbdiacruc {
    unsigned int diacr, base, result;
};
