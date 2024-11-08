#pragma once

#define KDGKBTYPE 0x4B33 /* get keyboard type */
#define KB_84 0x01
#define KB_101 0x02 /* this is what we always answer */
#define KB_OTHER 0x03

#define K_RAW 0x00
#define K_XLATE 0x01
#define K_MEDIUMRAW 0x02
#define K_UNICODE 0x03
#define K_OFF 0x04
#define KDGKBMODE 0x4B44 /* gets current keyboard mode */
#define KDSKBMODE 0x4B45 /* sets current keyboard mode */
