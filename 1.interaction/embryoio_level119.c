#include <stdlib.h>
#include <unistd.h>
#include <glob.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <libgen.h>
#include <fcntl.h>
#include <string.h>

char* glob_embryoio() {
    glob_t result;
    glob("/challenge/em*", 0, NULL, &result);
    return result.gl_pathv[0];
}

void respond_to_challenge(int input_fd, int output_fd) {
    char buf[4096] = {};
    read(input_fd, buf, 4096);

    char* chal = strstr(buf, "solution for: ") + 14;

    int bc_pipe[2];
    pipe(bc_pipe);

    if (fork()) {
        write(bc_pipe[1], chal, strlen(chal));
        close(bc_pipe[1]);
        wait(NULL);
    } else {
        dup2(bc_pipe[0], 0);
        dup2(output_fd, 1);
        execlp("bc", NULL, NULL);
    }
}

void pwncollege() {
    mkfifo("/tmp/fifo_stdin", 0666);
    mkfifo("/tmp/fifo_stdout", 0666);
    if (fork()) {
        int fd1 = open("/tmp/fifo_stdin", O_WRONLY);
        int fd2 = open("/tmp/fifo_stdout", O_RDONLY);
        
        respond_to_challenge(fd2, fd1);

        char buf[4096] = {};
        read(fd2, buf, 4096);
        write(1, buf, 4096);
    } else {
        int fd1 = open("/tmp/fifo_stdin", O_RDONLY);
        int fd2 = open("/tmp/fifo_stdout", O_WRONLY);
        dup2(fd1, 0);
        dup2(fd2, 1);
        char* bin_path = glob_embryoio();
        char* base_name = basename(bin_path);
        execve(bin_path, NULL, NULL);
    }
}

int main() {
    pwncollege();
}