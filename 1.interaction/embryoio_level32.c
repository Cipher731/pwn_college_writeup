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
        char* envp[2] = {"ejtqhd=oonqelcevp", NULL};
        execle("/challenge/embryoio_level32", "embryoio_level32", NULL, envp);
    }
}

int main() {
    pwncollege();
}