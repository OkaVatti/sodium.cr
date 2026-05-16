#include <stddef.h>

#if defined(__APPLE__)

__attribute__((visibility("default")))
void explicit_bzero(void *buf, size_t len) {
    volatile unsigned char *p = (volatile unsigned char *)buf;
    while (len--) {
        *p++ = 0;
    }
}

#endif
