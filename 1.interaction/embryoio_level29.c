#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

void pwncollege() {
    int pid;
    if (pid = fork()) {
        wait(NULL);
    } else {
        execl("/challenge/embryoio_level29", NULL);
    }
}

int main() {
    pwncollege();
}