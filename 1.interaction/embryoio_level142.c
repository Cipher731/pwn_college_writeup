#include <stdlib.h>
#include <unistd.h>
#include <glob.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <libgen.h>
#include <fcntl.h>
#include <stdio.h>

char* glob_embryoio() {
    glob_t result;
    glob("/challenge/em*", 0, NULL, &result);
    return result.gl_pathv[0];
}

int pwncollege() {
    if (!fork()) {
        char* bin_path = glob_embryoio();
        char* base_name = basename(bin_path);
        execl(bin_path, "challenge", NULL);
    }
    
    sleep(1);

    int sock, client_fd;
    struct sockaddr_in serv_addr;
    char buffer[1024] = {};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(1112);

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }
  
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(1112);

    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        printf( "\nInvalid address/ Address not supported \n");
        return -1;
    }
  
    if ((client_fd = connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr))) < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }

    sleep(1);
    char sock_fd[16] = {};
    sprintf(sock_fd, "%d", sock);
    if (!fork()) {
        execl("/usr/bin/python", "/usr/bin/python", "/home/hacker/challenges/1.interaction/embryoio_level142.py", sock_fd, NULL);
    }
    close(sock);
    while (wait(NULL) > 0);
}

int main() {
    pwncollege();
}