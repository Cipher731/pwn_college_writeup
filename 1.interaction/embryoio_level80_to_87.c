#include <stdlib.h>
#include <unistd.h>
#include <glob.h>
#include <sys/wait.h>
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
        chdir("/tmp/pwalfk");
        int fd = open("tuniny", O_RDONLY);
        dup2(fd, 0);
        
        char* bin_path = glob_embryoio();
        char* base_name = basename(bin_path);
        char* argv[200] = {};
        // char* envp[] = {"47=xhtaeanvhg", NULL};
        char* envp[] = {"148=ribdvcfzor", NULL};
        for (int i = 0; i < 200; i++) {
            argv[i] = "";
        }
        argv[23] = "gnpqcnflss";
        argv[176] = "cmvkzxmwri";
        argv[199] = NULL;
        execve(bin_path, argv, envp);
        // execve(bin_path, NULL, envp);
    }
}

int main() {
    pwncollege();
}