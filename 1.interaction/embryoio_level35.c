#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

void pwncollege() {
    // int fd;
    // fd = open("/tmp/vkgxdf", O_WRONLY | O_CREAT);
    if (fork()) {
        wait(NULL);
    } else {
        // dup2(fd, 1);
        // dup2(fd, 2);
        const char* envp[] = {NULL};
        execle("/challenge/embryoio_level35", "embryoio_level35", NULL, envp);
    }
}

int main() {
    pwncollege();
}