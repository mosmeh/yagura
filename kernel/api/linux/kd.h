#pragma once

#define GIO_CMAP 0x4B70 // gets colour palette on VGA+
#define PIO_CMAP 0x4B71 // sets colour palette on VGA+

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

#define KDFONTOP 0x4b72

struct console_font_op {
    unsigned int op;            // operation code KD_FONT_OP_*
    unsigned int flags;         // KD_FONT_FLAG_*
    unsigned int width, height; // font size
    unsigned int charcount;

    // font data with vpitch fixed to 32 for KD_FONT_OP_SET/GET
    unsigned char* data;
};

// Set font
#define KD_FONT_OP_SET 0

// Get font
#define KD_FONT_OP_GET 1

// Set font to default, data points to name / NULL
#define KD_FONT_OP_SET_DEFAULT 2

// Obsolete, do not use
#define KD_FONT_OP_COPY 3

// Set font with vpitch = height
#define KD_FONT_OP_SET_TALL 4

// Get font with vpitch = height
#define KD_FONT_OP_GET_TALL 5
