#define WIN32_LEAN_AND_MEAN
#include "context.h"
#include "windows.h"
#include "stdio.h"
#include <stdarg.h>

#undef printf

int do_logging = 0;
int do_restart = 0;

int gdb_log_printf(const char* fmt, ...) {
    va_list ap;
    int n;

    if (!do_logging)
        return 0;

    va_start(ap, fmt);
    n = vprintf(fmt, ap);
    va_end(ap);
    return n;
}

int hexval(int c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/*
   hex_lut[b] holds the two ASCII hex characters for byte b, packed so
   that a single little-endian 16-bit store writes the high-nibble char
   to *p and the low-nibble char to *(p+1).
*/
#define HEX_ENTRY(hi, lo) ((unsigned short)((((unsigned char)(lo)) << 8) | (unsigned char)(hi)))
#define HEX_ROW(hi)                                                                                                                   \
    HEX_ENTRY(hi, '0'), HEX_ENTRY(hi, '1'), HEX_ENTRY(hi, '2'), HEX_ENTRY(hi, '3'), HEX_ENTRY(hi, '4'), HEX_ENTRY(hi, '5'),           \
        HEX_ENTRY(hi, '6'), HEX_ENTRY(hi, '7'), HEX_ENTRY(hi, '8'), HEX_ENTRY(hi, '9'), HEX_ENTRY(hi, 'a'), HEX_ENTRY(hi, 'b'),       \
        HEX_ENTRY(hi, 'c'), HEX_ENTRY(hi, 'd'), HEX_ENTRY(hi, 'e'), HEX_ENTRY(hi, 'f')

static const unsigned short hex_lut[256] = {HEX_ROW('0'), HEX_ROW('1'), HEX_ROW('2'), HEX_ROW('3'), HEX_ROW('4'), HEX_ROW('5'),
                                            HEX_ROW('6'), HEX_ROW('7'), HEX_ROW('8'), HEX_ROW('9'), HEX_ROW('a'), HEX_ROW('b'),
                                            HEX_ROW('c'), HEX_ROW('d'), HEX_ROW('e'), HEX_ROW('f')};

#undef HEX_ENTRY
#undef HEX_ROW

void put_hex_byte(char* out, unsigned char b) {
    *(unsigned short*)out = hex_lut[b];
}

char* append_hex_byte(char* p, unsigned char b) {
    *(unsigned short*)p = hex_lut[b];
    return p + 2;
}

char* append_u32_le(char* p, DWORD v) {
    p = append_hex_byte(p, (unsigned char)(v & 0xff));
    p = append_hex_byte(p, (unsigned char)((v >> 8) & 0xff));
    p = append_hex_byte(p, (unsigned char)((v >> 16) & 0xff));
    p = append_hex_byte(p, (unsigned char)((v >> 24) & 0xff));
    return p;
}

int decode_hex_string_until_comma(const char* in, char* out, int outsz, const char** after) {
    int n = 0;

    while (*in && *in != ',') {
        int hi, lo;

        if (!in[1])
            return 0;

        hi = hexval((unsigned char)in[0]);
        lo = hexval((unsigned char)in[1]);

        if (hi < 0 || lo < 0)
            return 0;

        if (n < outsz - 1)
            out[n++] = (char)((hi << 4) | lo);

        in += 2;
    }

    out[n] = 0;

    if (after)
        *after = in;

    return *in == ',';
}

char* append_escaped_binary(char* p, char* end, const unsigned char* buf, int len) {
    int i;

    for (i = 0; i < len; ++i) {
        unsigned char c = buf[i];

        if (c == '$' || c == '#' || c == '}' || c == '*') {
            if (p + 2 >= end)
                break;

            *p++ = '}';
            *p++ = (char)(c ^ 0x20);
        } else {
            if (p + 1 >= end)
                break;

            *p++ = (char)c;
        }
    }

    *p = 0;
    return p;
}

char* append_hex_string(char* p, const char* s) {
    while (*s) {
        p = append_hex_byte(p, (unsigned char)*s);
        s++;
    }
    return p;
}

int stricmp_slash_insensitive(const char* a, const char* b) {
    while (*a && *b) {
        char ca = *a++;
        char cb = *b++;

        if (ca == '\\')
            ca = '/';
        if (cb == '\\')
            cb = '/';

        if (ca >= 'A' && ca <= 'Z')
            ca = (char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z')
            cb = (char)(cb - 'A' + 'a');

        if (ca != cb)
            return ca - cb;
    }

    return *a - *b;
}

int decode_hex_string_all(const char* in, char* out, int outsz) {
    int n = 0;

    while (*in) {
        int hi, lo;

        if (!in[1])
            return 0;

        hi = hexval((unsigned char)in[0]);
        lo = hexval((unsigned char)in[1]);

        if (hi < 0 || lo < 0)
            return 0;

        if (n < outsz - 1)
            out[n++] = (char)((hi << 4) | lo);

        in += 2;
    }

    out[n] = 0;
    return 1;
}

void make_posix_win_path(const char* win_path, char* out, int outsz) {
    int i, j = 0;

    if (outsz <= 0)
        return;

    if (!win_path || !win_path[0]) {
        strncpy(out, "/unknown", outsz - 1);
        out[outsz - 1] = 0;
        return;
    }

    out[j++] = '/';

    for (i = 0; win_path[i] && j < outsz - 1; ++i) {
        char c = win_path[i];
        if (c == '\\')
            c = '/';
        out[j++] = c;
    }

    out[j] = 0;
}

void xml_escape_append(char** pp, char* end, const char* s) {
    char* p = *pp;

    while (*s && p < end - 8) {
        switch (*s) {
            case '&':
                p += sprintf(p, "&amp;");
                break;
            case '<':
                p += sprintf(p, "&lt;");
                break;
            case '>':
                p += sprintf(p, "&gt;");
                break;
            case '"':
                p += sprintf(p, "&quot;");
                break;
            case '\'':
                p += sprintf(p, "&apos;");
                break;
            default:
                *p++ = *s;
                break;
        }

        s++;
    }

    *p = '\0';
    *pp = p;
}

void protect_to_permissions(DWORD protect, char* out) {
    int r = 0, w = 0, x = 0;

    protect &= 0xff; /* remove PAGE_GUARD / PAGE_NOCACHE-ish bits */

    switch (protect) {
        case PAGE_READONLY:
            r = 1;
            break;

        case PAGE_READWRITE:
        case PAGE_WRITECOPY:
            r = 1;
            w = 1;
            break;

        case PAGE_EXECUTE:
            x = 1;
            break;

        case PAGE_EXECUTE_READ:
            r = 1;
            x = 1;
            break;

        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            r = 1;
            w = 1;
            x = 1;
            break;

        default:
            break;
    }

    out[0] = r ? 'r' : '-';
    out[1] = w ? 'w' : '-';
    out[2] = x ? 'x' : '-';
    out[3] = '\0';
}

void make_proc_maps_path(const char* win_path, char* out, int outsz) {
    int i, j = 0;

    if (!win_path || !win_path[0]) {
        strncpy(out, "/unknown", outsz - 1);
        out[outsz - 1] = 0;
        return;
    }

    out[j++] = '/';

    for (i = 0; win_path[i] && j < outsz - 1; ++i) {
        char c = win_path[i];
        if (c == '\\')
            c = '/';
        out[j++] = c;
    }

    out[j] = 0;
}

void make_lldb_module_path(const char* win_path, char* out, int outsz) {
    int i, j = 0;

    if (!win_path || !win_path[0]) {
        strncpy(out, "unknown", outsz - 1);
        out[outsz - 1] = 0;
        return;
    }

    for (i = 0; win_path[i] && j < outsz - 1; ++i) {
        char c = win_path[i];

        if (c == '\\')
            c = '/';

        /*
           If the source path is accidentally already /D:/foo,
           strip that leading slash for LLDB.
        */
        if (i == 0 && c == '/' && win_path[1] && win_path[2] == ':') {
            continue;
        }

        out[j++] = c;
    }

    out[j] = 0;
}

void normalize_module_query_path(const char* in, char* out, int outsz) {
    int i, j = 0;

    if (!in || !in[0]) {
        out[0] = 0;
        return;
    }

    /*
       Convert:
         /D:/main/foo.exe
         D:\main\foo.exe

       into:
         d:/main/foo.exe
    */

    if (in[0] == '/' && in[1] && in[2] == ':')
        in++;

    for (i = 0; in[i] && j < outsz - 1; ++i) {
        char c = in[i];

        if (c == '\\')
            c = '/';

        if (c >= 'A' && c <= 'Z')
            c = (char)(c - 'A' + 'a');

        out[j++] = c;
    }

    out[j] = 0;
}

int same_module_path(const char* a, const char* b) {
    char na[512];
    char nb[512];

    normalize_module_query_path(a, na, sizeof(na));
    normalize_module_query_path(b, nb, sizeof(nb));

    return strcmp(na, nb) == 0;
}
