#include <stdlib.h>
#include <unistd.h>
#include <glob.h>
#include <sys/wait.h>
#include <libgen.h>
#include <fcntl.h>
/* 
hacker@embryoio_level124:~/challenges$ kill -s SIGUSR1 207
hacker@embryoio_level124:~/challenges$ kill -s SIGHUP 207
hacker@embryoio_level124:~/challenges$ kill -s SIGUSR2 207
hacker@embryoio_level124:~/challenges$ kill -s SIGHUP 207
hacker@embryoio_level124:~/challenges$ kill -s SIGUSR2 207
*/

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
        execve(bin_path, NULL, NULL);
    }
}

int main() {
    pwncollege();
}