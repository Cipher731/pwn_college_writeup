#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <glob.h>
#include <libgen.h>
#include <string.h>

char* glob_embryoio() {
    glob_t result;
    glob("/challenge/em*", 0, NULL, &result);
    return result.gl_pathv[0];
}

void pwncollege() {
    int fd1[2];
    int fd2[2];
    pipe(fd1);
    pipe(fd2);
    if (fork()) {
        if (fork()) {
            sleep(1);
            close(fd1[0]);

            char password[10] = "qysjuuaj\n";

            write(fd1[1], password, strlen(password));
            close(fd1[1]);

            wait(NULL);
            wait(NULL);
        } else {
            close(fd1[1]);
            dup2(fd1[0], 0);

            close(fd2[0]);
            dup2(fd2[1], 1);
            dup2(fd2[1], 2);

            execlp("rev", "rev", NULL);
        }
    } else {
        close(fd1[0]);
        close(fd1[1]);
        close(fd2[1]);
        dup2(fd2[0], 0);
        
        char* envp[] = {NULL};
        char* bin_path = glob_embryoio();
        char* base_name = basename(bin_path);

        execle(bin_path, base_name, NULL, envp);
    }

}

int main() {
    pwncollege();
}