#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "stdio.h"
#include "string.h"

int sprintf(char* buffer, const char* format, ...) {
    va_list args;
    va_start(args, format);
    int ret = vsnprintf(buffer, SIZE_MAX, format, args);
    va_end(args);
    return ret;
}

int snprintf(char* buffer, size_t bufsz, const char* format, ...) {
    va_list args;
    va_start(args, format);
    int ret = vsnprintf(buffer, bufsz, format, args);
    va_end(args);
    return ret;
}

int vsprintf(char* buffer, const char* format, va_list args) {
    return vsnprintf(buffer, SIZE_MAX, format, args);
}

static void itoa(int value, char* str, int radix) {
    char* c = str;
    unsigned uvalue = value;

    if (radix == 10 && value < 0) {
        *c++ = '-';
        str++;
        uvalue = -value;
    }

    do {
        unsigned mod = uvalue % radix;
        *c++ = (mod < 10) ? mod + '0' : mod - 10 + 'a';
    } while (uvalue /= radix);

    *c = 0;

    char* p1 = str;
    char* p2 = c - 1;
    while (p1 < p2) {
        char tmp = *p1;
        *p1 = *p2;
        *p2 = tmp;
        p1++;
        p2--;
    }
}

// NOLINTNEXTLINE(readability-non-const-parameter)
int vsnprintf(char* buffer, size_t size, const char* format, va_list args) {
    if (size == 0)
        return 0;

    size_t idx = 0;

#define PUT(c)                                                                 \
    do {                                                                       \
        buffer[idx++] = (c);                                                   \
        if (idx >= size)                                                       \
            goto too_long;                                                     \
    } while (0)

    char ch;
    while ((ch = *format++) != 0) {
        if (ch != '%') {
            PUT(ch);
            continue;
        }

        ch = *format++;
        if (ch == '%') {
            PUT('%');
            continue;
        }

        bool alternative_form = false;
        bool left_justify = false;
        bool pad0 = false;
        size_t pad_len = 0;
        for (;;) {
            if (!alternative_form && ch == '#') {
                alternative_form = true;
                ch = *format++;
            } else if (!left_justify && ch == '-') {
                left_justify = true;
                ch = *format++;
            } else if (!pad0 && ch == '0') {
                pad0 = true;
                ch = *format++;
            } else {
                break;
            }
        }
        while ('0' <= ch && ch <= '9') {
            pad_len = pad_len * 10 + ch - '0';
            ch = *format++;
        }

        switch (ch) {
        case 'c':
            PUT((char)va_arg(args, int));
            break;
        case 'p':
        case 'x':
            if (alternative_form || ch == 'p') {
                PUT('0');
                if (pad_len > 0)
                    --pad_len;
                PUT('x');
                if (pad_len > 0)
                    --pad_len;
            }
            // falls through
        case 'd':
        case 'i':
        case 'u': {
            char num_buf[20];
            int radix = (ch == 'x' || ch == 'p') ? 16 : 10;
            itoa(va_arg(args, int), num_buf, radix);

            size_t len = strlen(num_buf);
            if (!left_justify && pad_len > len) {
                for (size_t i = 0; i < pad_len - len; ++i)
                    PUT(pad0 ? '0' : ' ');
            }
            for (size_t i = 0; i < len; ++i)
                PUT(num_buf[i]);
            if (left_justify && pad_len > len) {
                for (size_t i = 0; i < pad_len - len; ++i)
                    PUT(' ');
            }

            break;
        }
        case 's': {
            const char* str = va_arg(args, const char*);
            if (!str)
                str = "(null)";
            while (*str)
                PUT(*str++);
            break;
        }
        default:
            PUT('?');
            break;
        }
    }

too_long:
    buffer[idx < size ? idx : size - 1] = '\0';
    return idx;
}
