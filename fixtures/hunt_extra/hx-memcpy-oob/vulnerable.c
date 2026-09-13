/*
 * INTENTIONALLY VULNERABLE — hunt_extra micro-fixture (Juliet-shaped).
 * Classic unbounded memcpy into a fixed buffer (CWE-122 style).
 * Do not deploy.
 */
#include <string.h>

#define BUF_SIZE 8

static char g_buf[BUF_SIZE];

void copy_user(char *dst, const char *src, unsigned n)
{
    /* no check that n <= BUF_SIZE — attacker-controlled length */
    memcpy(dst, src, n);
}

void entry(const char *src, unsigned n)
{
    copy_user(g_buf, src, n);
}
