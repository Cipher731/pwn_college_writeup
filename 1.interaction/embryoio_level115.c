#include <stdlib.h>
#include <unistd.h>
#include <glob.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <libgen.h>
#include <fcntl.h>

char* glob_embryoio() {
    glob_t result;
    glob("/challenge/em*", 0, NULL, &result);
    return result.gl_pathv[0];
}

void pwncollege() {
    if (fork()) {
        wait(NULL);
    } else {
        char* bin_path = glob_embryoio();
        char* base_name = basename(bin_path);
        char* argv[200] = {};
        argv[0] = "rpllha";
        execve(bin_path, argv, NULL);
    }
}

int main() {
    pwncollege();
}