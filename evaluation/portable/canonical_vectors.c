#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct kv { const char *key; const char *raw; };

static size_t utf16_units(const char *s, uint16_t *out, size_t cap) {
    const unsigned char *p = (const unsigned char *)s;
    size_t n = 0;
    while (*p != 0) {
        uint32_t cp;
        if (*p < 0x80) { cp = *p++; }
        else if ((*p & 0xE0) == 0xC0) { cp = (uint32_t)(*p++ & 0x1F) << 6; cp |= (uint32_t)(*p++ & 0x3F); }
        else if ((*p & 0xF0) == 0xE0) { cp = (uint32_t)(*p++ & 0x0F) << 12; cp |= (uint32_t)(*p++ & 0x3F) << 6; cp |= (uint32_t)(*p++ & 0x3F); }
        else { cp = (uint32_t)(*p++ & 0x07) << 18; cp |= (uint32_t)(*p++ & 0x3F) << 12; cp |= (uint32_t)(*p++ & 0x3F) << 6; cp |= (uint32_t)(*p++ & 0x3F); }
        if (cp <= 0xFFFF) {
            if (n >= cap) abort();
            out[n++] = (uint16_t)cp;
        } else {
            cp -= 0x10000;
            if (n + 1 >= cap) abort();
            out[n++] = (uint16_t)(0xD800u + (cp >> 10));
            out[n++] = (uint16_t)(0xDC00u + (cp & 0x3FFu));
        }
    }
    return n;
}

static int key_cmp(const void *aa, const void *bb) {
    const struct kv *a = (const struct kv *)aa;
    const struct kv *b = (const struct kv *)bb;
    uint16_t au[128], bu[128];
    size_t an = utf16_units(a->key, au, 128), bn = utf16_units(b->key, bu, 128);
    size_t n = an < bn ? an : bn;
    for (size_t i = 0; i < n; ++i) {
        if (au[i] < bu[i]) return -1;
        if (au[i] > bu[i]) return 1;
    }
    return an < bn ? -1 : an > bn ? 1 : 0;
}

static void quoted(FILE *out, const char *s) {
    const unsigned char *p = (const unsigned char *)s;
    fputc('"', out);
    while (*p != 0) {
        unsigned char c = *p++;
        switch (c) {
            case '"': fputs("\\\"", out); break;
            case '\\': fputs("\\\\", out); break;
            case '\b': fputs("\\b", out); break;
            case '\t': fputs("\\t", out); break;
            case '\n': fputs("\\n", out); break;
            case '\f': fputs("\\f", out); break;
            case '\r': fputs("\\r", out); break;
            default:
                if (c <= 0x1F) fprintf(out, "\\u%04x", (unsigned)c);
                else fputc((int)c, out);
        }
    }
    fputc('"', out);
}

static void object_line(const char *name, const struct kv *input, size_t count) {
    struct kv copy[8];
    if (count > 8) abort();
    memcpy(copy, input, count * sizeof(copy[0]));
    qsort(copy, count, sizeof(copy[0]), key_cmp);
    printf("%s\t{", name);
    for (size_t i = 0; i < count; ++i) {
        if (i) fputc(',', stdout);
        quoted(stdout, copy[i].key);
        fputc(':', stdout);
        fputs(copy[i].raw, stdout);
    }
    puts("}");
}

int main(void) {
    const struct kv order[] = {{"b", "2"}, {"a", "1"}};
    object_line("object_order", order, 2);

    fputs("string_escape\t", stdout);
    quoted(stdout, "line\n\"slash\\ snowman \xE2\x98\x83");
    fputc('\n', stdout);

    const struct kv nested[] = {{"z", "[true,false,null,-9007199254740991,9007199254740991]"}, {"a", "{\"k\":\"v\"}"}};
    object_line("nested_limits", nested, 2);

    const struct kv unicode_keys[] = {{"\xEE\x80\x80", "\"bmp\""}, {"\xF0\x9F\x98\x80", "\"astral\""}};
    object_line("utf16_order", unicode_keys, 2);

    const struct kv empty[] = {{"array", "[]"}, {"object", "{}"}, {"null", "null"}};
    object_line("empty", empty, 3);
    return 0;
}
