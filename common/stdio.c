#include <common/stdarg.h>
#include <common/stdbool.h>
#include <common/stddef.h>
#include <common/stdint.h>
#include <common/stdio.h>
#include <common/string.h>

int sprintf(char* buffer, const char* format, ...) {
    va_list args;
    va_start(args, format);
    int ret = vsnprintf(buffer, PTRDIFF_MAX, format, args);
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
    return vsnprintf(buffer, PTRDIFF_MAX, format, args);
}

static size_t utoa(unsigned long long value, char* str, unsigned radix) {
    char* c = str;
    for (;;) {
        unsigned long long r = value % radix;
        value /= radix;
        *c++ = (r < 10) ? r + '0' : r - 10 + 'a';
        if (value == 0)
            break;
    }
    size_t n = c - str;

    char* p1 = str;
    char* p2 = c - 1;
    while (p1 < p2) {
        char tmp = *p1;
        *p1 = *p2;
        *p2 = tmp;
        p1++;
        p2--;
    }

    return n;
}

enum length_spec {
    LENGTH_DEFAULT,
    LENGTH_LONG,
    LENGTH_LONG_LONG,
};

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

        enum length_spec length_spec = LENGTH_DEFAULT;
        switch (ch) {
        case 'h':
            if (*format == 'h') {
                // char (promoted to int)
                ++format;
            } else {
                // short (promoted to int)
            }
            ch = *format++;
            break;
        case 'l':
            if (*format == 'l') {
                length_spec = LENGTH_LONG_LONG;
                ++format;
            } else {
                length_spec = LENGTH_LONG;
            }
            ch = *format++;
            break;
        case 'z': // size_t
            length_spec = LENGTH_LONG;
            ch = *format++;
            break;
        }

        char num_buf[20];
        size_t num_len = 0;
        unsigned radix = 10;

#define PUT_NUM_PREFIX(c)                                                      \
    if (pad0) {                                                                \
        PUT(c);                                                                \
        --pad_len;                                                             \
    } else {                                                                   \
        num_buf[num_len++] = c;                                                \
    }

        switch (ch) {
        case 'c':
            PUT((char)va_arg(args, int));
            break;
        case 'p':
            if (pad_len == 0) {
                pad0 = true;
                pad_len = sizeof(void*) * 2;
            }
            length_spec = LENGTH_LONG;
            // falls through
        case 'x':
            if (alternative_form) {
                PUT_NUM_PREFIX('0');
                PUT_NUM_PREFIX('x');
            }
            radix = 16;
            // falls through
        case 'd':
        case 'i':
        case 'u': {
            bool is_signed = ch == 'd' || ch == 'i';
            uintmax_t value;
            // NOLINTBEGIN(bugprone-branch-clone) int vs. long on 32-bit arch
            switch (length_spec) {
            case LENGTH_DEFAULT:
                if (is_signed)
                    value = va_arg(args, int);
                else
                    value = va_arg(args, unsigned int);
                break;
            case LENGTH_LONG:
                if (is_signed)
                    value = va_arg(args, long);
                else
                    value = va_arg(args, unsigned long);
                break;
            case LENGTH_LONG_LONG:
                if (is_signed)
                    value = va_arg(args, long long);
                else
                    value = va_arg(args, unsigned long long);
                break;
            default:
                __builtin_unreachable();
            }
            // NOLINTEND(bugprone-branch-clone)

            if (is_signed && value > INTMAX_MAX) {
                PUT_NUM_PREFIX('-');
                value = -value;
            }
            num_len += utoa(value, num_buf + num_len, radix);

            if (!left_justify && pad_len > num_len) {
                for (size_t i = 0; i < pad_len - num_len; ++i)
                    PUT(pad0 ? '0' : ' ');
            }
            for (size_t i = 0; i < num_len; ++i)
                PUT(num_buf[i]);
            if (left_justify && pad_len > num_len) {
                for (size_t i = 0; i < pad_len - num_len; ++i)
                    PUT(' ');
            }

            break;
        }
        case 's': {
            const char* str = va_arg(args, const char*);
            if (!str)
                str = "(null)";
            size_t len = strlen(str);
            if (!left_justify && pad_len > len) {
                for (size_t i = 0; i < pad_len - len; ++i)
                    PUT(' ');
            }
            while (*str)
                PUT(*str++);
            if (left_justify && pad_len > len) {
                for (size_t i = 0; i < pad_len - len; ++i)
                    PUT(' ');
            }
            break;
        }
        default:
            PUT('%');
            PUT(ch);
            break;
        }
    }

too_long:
    buffer[idx < size ? idx : size - 1] = '\0';
    return idx;
}
