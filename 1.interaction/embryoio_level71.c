#include <stdlib.h>
#include <unistd.h>

int main() {
    char* argv[60] = {};
    for (int i = 0; i < 60; i++) {
        argv[i] = "";
    }
    argv[0] = "embryoio_level71";
    argv[53] = "xplpklobta";
    argv[59] = NULL;
    char* envp[] = {"46=kznzlshrhb", NULL};
    execve("/challenge/embryoio_level71", argv, envp);
    return 0;
}