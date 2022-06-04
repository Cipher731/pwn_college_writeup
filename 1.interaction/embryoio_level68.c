#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <glob.h>
#include <libgen.h>
#include <string.h>
#include <stdlib.h>

char* glob_embryoio() {
    glob_t result;
    glob("/challenge/em*", 0, NULL, &result);
    return result.gl_pathv[0];
}

void pwncollege() {
    char* envp[] = {"289=zgwpbyxkbv", NULL};
    clearenv();
    putenv("289=zgwpbyxkbv");
    char* bin_path = glob_embryoio();
    char* base_name = basename(bin_path);

    execl(bin_path, NULL);
}

int main() {
    pwncollege();
}