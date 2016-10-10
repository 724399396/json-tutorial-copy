#include "leptjson.h"
#include <assert.h> /** assert */
#include <stdlib.h> /** NULL strtod */
#include <errno.h> /** errno ERANGE */
#include <math.h> /** HUGE_VAL */
#include <string.h> /** memcpy */

#ifndef LEPT_PARSE_STACK_INIT_SIZE
#define LEPT_PARSE_STACK_INIT_SIZE 256
#endif

#define EXPECT(p,ch) do {\
        assert(*p->json == ch);\
        p->json++;\
        } while(0)
#define ISDIGIT(x) ((x) >= '0' && (x) <= '9')
#define ISDIGIT1TO9(x) ((x) >= '1' && (x) <= '9')
#define PUTC(c, ch) do { *(char *)lept_context_push(c, sizeof(char)) = ch; } while(0)
#define STRING_ERROR(ret) do { c->top = head; return ret; } while(0)
#define ISHEX(x) (((x) >= 'a' && (x) <= 'f') || ((x) >= 'A' && (x) <= 'F')) || ISDIGIT(x)

typedef struct {
    const char *json;
    char *stack;
    size_t top, size;
} lept_context;

static void *lept_context_push(lept_context *c, size_t size) {
    void *ret;
    assert(size > 0);
    if (c->top + size >= c->size) {
        if (c->size == 0)
            c->size = LEPT_PARSE_STACK_INIT_SIZE;
        while (c->top + size >= c->size)
            c->size += c->size >> 1;
        c->stack = (char *)realloc(c->stack, c->size);
    }
    ret = c->stack + c->top;
    c->top += size;
    return ret;
}

static void *lept_context_pop(lept_context *c, size_t size) {
    assert(c->top >= size);
    return c->stack + (c->top -= size);
}

static int lept_parse_literal(lept_value *v, lept_context *c, const char *literal, lept_type type) {
    size_t i;
    EXPECT(c, literal[0]);
    for (i = 0; literal[i+1]; i++)
        if (c->json[i] != literal[i+1])
            return LEPT_PARSE_INVALID_VALUE;
    c->json += i;
    v->type = type;
    return LEPT_PARSE_OK;
}

static int lept_parse_number(lept_value *v, lept_context *c) {
    const char *p = c->json;
    if (*p == '-') p++;
    if (*p == '0') {
        p++;
    } else {
        if (!ISDIGIT1TO9(*p))
            return LEPT_PARSE_INVALID_VALUE;
        for (p++; ISDIGIT(*p); p++) ;
    }
    if (*p == '.') {
        p++;
        if (!ISDIGIT(*p))
            return LEPT_PARSE_INVALID_VALUE;
        for (p++; ISDIGIT(*p); p++) ;
    }
    if (*p == 'e' || *p == 'E') {
        p++;
        if (*p == '+' || *p == '-')
            p++;
        if (!ISDIGIT(*p))
            return LEPT_PARSE_INVALID_VALUE;
        for (p++; ISDIGIT(*p); p++) ;
    }
    errno = 0;
    v->u.n = strtod(c->json, NULL);
    if (errno == ERANGE && (v->u.n == HUGE_VAL || v->u.n == -HUGE_VAL))
        return LEPT_PARSE_NUMBER_TOO_BIG;
    c->json = p;
    v->type = LEPT_NUMBER;
    return LEPT_PARSE_OK;
}

static void lept_encode_utf8(lept_context *c, unsigned int u) {
    assert(u >= 0x0000 && u <= 0x10FFFF);
    if (u >= 0x0000 && u <= 0x007F) {
        PUTC(c,         u       & 0x7F);
    } else if (u >= 0x0080 && u <= 0x07FF) {
        PUTC(c, 0xC0 | (u >> 6  & 0x1F));
        PUTC(c, 0x80 | (u       & 0x3F));
    } else if (u >= 0x0800 && u <= 0xFFFF) {
        PUTC(c, 0xE0 | (u >> 12 & 0xFF));
        PUTC(c, 0x80 | (u >> 6  & 0x3F));
        PUTC(c, 0x80 | (u       & 0x3F));
    } else if (u >= 0x10000 && u <= 0x10FFFF) {
        PUTC(c, 0xF0 | (u >> 18 & 0x07));
        PUTC(c, 0x80 | (u >> 12 & 0x3F));
        PUTC(c, 0x80 | (u >> 6  & 0x3F));
        PUTC(c, 0x80 | (u       & 0x3F));
    }
}

static const char *lept_parse_hex4(const char *p, unsigned int *u) {
    size_t i;
    
    for (i = 0, *u = 0; i < 4; i++) { 
        if (!(ISHEX(p[i])))
            return NULL;
        if (p[i] >= '0' && p[i] <= '9')            
            *u = *u * 16 + (p[i] - '0');
        else if (p[i] >= 'a' && p[i] <= 'f')
            *u = *u * 16 + (p[i] - 'a' + 10);
        else
            *u = *u * 16 + (p[i] - 'A' + 10);
    }
    return (p+4);
}

static int lept_parse_string(lept_value *v, lept_context *c) {
    size_t head = c->top, len;
    unsigned u;
    const char* p;
    EXPECT(c, '\"');
    p = c->json;
    for (;;) {
        char ch = *p++;
        switch (ch) {
        case '\"':
            len = c->top - head;
            lept_set_string(v, (const char *)lept_context_pop(c, len), len);
            c->json = p;
            return LEPT_PARSE_OK;
        case '\0':
            STRING_ERROR(LEPT_PARSE_MISS_QUOTATION_MARK);
        case '\\':
            switch (*p++) {
            case 'n':
                ch = '\n';
                PUTC(c, ch);
                break; 
            case '\\':
                ch = '\\';
                PUTC(c, ch);
                break;
            case '/':
                ch = '/';
                PUTC(c, ch);
                break;
            case 'b':
                ch = '\b';
                PUTC(c, ch);
                break;
            case 'f':
                ch = '\f';
                PUTC(c, ch);
                break;
            case 'r':
                ch = '\r';
                PUTC(c, ch);                
                break;
            case 't':
                ch = '\t';
                PUTC(c, ch);
                break;
            case '"':
                ch = '"';
                PUTC(c, ch);
                break;
            case 'u':
                if (!(p = lept_parse_hex4(p, &u)))
                    STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
                if (u >= 0xd800 && u <= 0xdbff) {
                    if (*p++ != '\\')
                        STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                    if (*p++ != 'u')
                        STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                    unsigned h = u;
                    if (!(p = lept_parse_hex4(p, &u))) {
                        STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                    }
                    if (u <= 0xdc00 || u >= 0xdfff) {
                        STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                    }
                    u = 0x10000 + (h - 0xd800) * 0x400 + (u - 0xdc00);                    
                }
                lept_encode_utf8(c, u);
                break;
            default:
                STRING_ERROR(LEPT_PARSE_INVALID_STRING_ESCAPE);
            }
            break;
        default:
            if ((unsigned char)ch < 0x20) { 
                STRING_ERROR(LEPT_PARSE_INVALID_STRING_CHAR);
                }
            PUTC(c, ch);
            break;
        }        
    }
}

static void lept_parse_whitespace(lept_context *c) {
   const char *p = c->json;
   while (*p == ' ' || *p == '\t' || *p == '\n')
       p++;
   c->json = p;
}

static int lept_parse_value(lept_context *, lept_value *);

static int lept_parse_array(lept_value *v, lept_context *c) {
    size_t size = 0;
    int ret;
    EXPECT(c, '[');
    lept_parse_whitespace(c);
    if (*c->json == ']') {
        c->json++;
        v->type = LEPT_ARRAY;
        v->u.a.size = 0;
        v->u.a.e = NULL;
        return LEPT_PARSE_OK;
    }
    for (;;) {
        lept_value e;
        lept_init(&e);
        lept_parse_whitespace(c);
        if ((ret = lept_parse_value(c, &e)) != LEPT_PARSE_OK) {
            if (size > 0) {
                v->type = LEPT_ARRAY;
                v->u.a.size = size;
                size *= sizeof(lept_value);
                memcpy(v->u.a.e = (lept_value *)malloc(size), lept_context_pop(c, size), size);
                lept_free(v);
            }
            return ret;
        }
        memcpy(lept_context_push(c, sizeof(lept_value)), &e, sizeof(lept_value));
        size++;
        lept_parse_whitespace(c);
        if (*c->json == ',')
            c->json++;
        else if (*c->json == ']') {
            c->json++;
            v->type = LEPT_ARRAY;
            v->u.a.size = size;
            size *= sizeof(lept_value);
            memcpy(v->u.a.e = (lept_value *)malloc(size), lept_context_pop(c, size), size);
            return LEPT_PARSE_OK;
        } else {
            if (size > 0) {
                v->type = LEPT_ARRAY;
                v->u.a.size = size;
                size *= sizeof(lept_value);
                memcpy(v->u.a.e = (lept_value *)malloc(size), lept_context_pop(c, size), size);
                lept_free(v);
            }
            return LEPT_PARSE_MISS_COMMA_OR_SQUARE_BRACKET;
        }
    }
}

static int lept_parse_value(lept_context *c, lept_value *v) {
    switch(*c->json) {
    case 'n':  return lept_parse_literal(v, c, "null", LEPT_NULL);
    case 't':  return lept_parse_literal(v, c, "true", LEPT_TRUE);
    case 'f':  return lept_parse_literal(v, c, "false", LEPT_FALSE);
    case '\0': return LEPT_PARSE_EXPECT_VALUE;
    case '"':  return lept_parse_string(v, c);
    case '[':  return lept_parse_array(v, c);
    default :  return lept_parse_number(v, c);
    }
}

int lept_parse(lept_value *v, const char *json) {
    lept_context c;
    int ret;
    assert(v != NULL);
    c.json = json;
    c.stack = NULL;
    c.top = c.size = 0;
    v->type = LEPT_NULL;
    lept_parse_whitespace(&c);
    if ((ret = lept_parse_value(&c,v)) == LEPT_PARSE_OK) {
        lept_parse_whitespace(&c);
        if (*c.json != '\0') {
            v->type = LEPT_NULL;
            return LEPT_PARSE_ROOT_NOT_SINGULAR;
        }
    }
    assert(c.top == 0);
    free(c.stack);
    return ret;
}

lept_type lept_get_type(lept_value *v) {
    assert(v != NULL);
    return v->type;
}

void lept_free(lept_value *v) {
    assert(v != NULL);
    if (v->type == LEPT_STRING)
        free(v->u.s.s);
    if (v->type == LEPT_ARRAY) {
        size_t t = lept_get_array_size(v);
        size_t i = 0;
        while (i < t)
            lept_free(lept_get_array_element(v, i++));
        if (t > 0)
            free(lept_get_array_element(v, 0)); 
    }
    v->type = LEPT_NULL;
}

int lept_get_boolean(const lept_value* v) {
    assert(v != NULL && (v->type == LEPT_TRUE || v->type == LEPT_FALSE));
    if (v->type == LEPT_TRUE)
        return 1;
    if (v->type == LEPT_FALSE)
        return 0;
}
void lept_set_boolean(lept_value *v, int b) {
    assert(v != NULL);
    if (b)
        v->type = LEPT_TRUE;
    else
        v->type = LEPT_FALSE;
}

double lept_get_number(const lept_value *v) {
    assert(v != NULL && v->type == LEPT_NUMBER);
    return v->u.n;
}
void lept_set_number(lept_value* v, double n) {
    assert(v != NULL);
    v->type = LEPT_NUMBER;
    v->u.n = n;
}

const char* lept_get_string(const lept_value *v) {
    assert(v != NULL && v->type == LEPT_STRING);
    return v->u.s.s;
}
size_t lept_get_string_length(const lept_value *v) {
    assert(v != NULL && v->type == LEPT_STRING);
    return v->u.s.len;
}
void lept_set_string(lept_value* v, const char *s, size_t len) {
    assert(v != NULL && (s != NULL || len == 0));
    lept_free(v);
    v->type = LEPT_STRING;
    v->u.s.s = (char *)malloc(len + 1);
    memcpy(v->u.s.s, s, len);
    v->u.s.s[len] = '\0';
    v->u.s.len = len;
}

size_t lept_get_array_size(const lept_value *v) {
    assert(v != NULL && v->type == LEPT_ARRAY);
    return v->u.a.size;
}
lept_value *lept_get_array_element(const lept_value *v, size_t index) {
    assert(v != NULL && v->type == LEPT_ARRAY);
    assert(index < v->u.a.size);
    return &v->u.a.e[index];
}
