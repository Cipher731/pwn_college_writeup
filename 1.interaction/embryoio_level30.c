#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

void pwncollege() {
    int fd[2];
    pipe(fd);
    write(fd[1], "fihnpasf\n", 9);
    close(fd[1]);
    if (fork()) {
        wait(NULL);
    } else {
        dup2(fd[0], 0);
        execl("/challenge/embryoio_level30", NULL);
    }
}

int main() {
    pwncollege();
}