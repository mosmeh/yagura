#pragma once

#define SCHAR_MAX __SCHAR_MAX__
#define SHRT_MAX __SHRT_MAX__
#define INT_MAX __INT_MAX__
#define LONG_MAX __LONG_MAX__

#define SCHAR_MIN (-SCHAR_MAX - 1)
#define SHRT_MIN (-SHRT_MAX - 1)
#define INT_MIN (-__INT_MAX__ - 1)
#define LONG_MIN (-LONG_MAX - 1L)

#define UCHAR_MAX (__SCHAR_MAX__ * 2 + 1)
#define USHRT_MAX (__SHRT_MAX__ * 2U + 1U)
#define UINT_MAX (__INT_MAX__ * 2U + 1U)
#define ULONG_MAX (__LONG_MAX__ * 2UL + 1UL)

#define CHAR_BIT __CHAR_BIT__

#define CHAR_WIDTH CHAR_BIT
#define SCHAR_WIDTH CHAR_BIT
#define UCHAR_WIDTH CHAR_BIT

#define SHRT_WIDTH __SHRT_WIDTH__
#define USHRT_WIDTH SHRT_WIDTH

#define INT_WIDTH __INT_WIDTH__
#define UINT_WIDTH INT_WIDTH

#define LONG_WIDTH __LONG_WIDTH__
#define ULONG_WIDTH LONG_WIDTH

#define LLONG_WIDTH (CHAR_BIT * sizeof(long long))
#define ULLONG_WIDTH LLONG_WIDTH

#define LLONG_MAX __LONG_LONG_MAX__
#define LLONG_MIN (-__LONG_LONG_MAX__ - 1LL)
#define ULLONG_MAX (__LONG_LONG_MAX__ * 2ULL + 1ULL)
