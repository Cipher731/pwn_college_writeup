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
    mkfifo("/tmp/fifo", 0666);
    if (fork()) {
        int fd = open("/tmp/fifo", O_WRONLY);
        write(fd, "oagroiey", 8);
        close(fd);
        wait(NULL);
    } else {
        int fd = open("/tmp/fifo", O_RDONLY);
        dup2(fd, 0);
        char* bin_path = glob_embryoio();
        char* base_name = basename(bin_path);
        execve(bin_path, NULL, NULL);
    }
}

int main() {
    pwncollege();
}