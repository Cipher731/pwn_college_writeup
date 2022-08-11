// gcc -shared -o level50.so -fPIC level50.c
// ssh-keygen -D ./level50.so
#include <stdlib.h>
#include <stdio.h>

static void ctor() __attribute__((constructor));

void ctor() {
    FILE *ptr = fopen("/flag", "r");
    char buf[4096] = {};
    fgets(buf, 4096, ptr);
    puts(buf);
}