#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *def[] = { "/etc/passwd", "/etc/shadow", NULL };
    const char **list = (argc > 1) ? (const char **)(argv + 1) : def;
    for (int i = 0; list[i]; i++) {
        int fd = open(list[i], O_RDONLY);
        if (fd >= 0) {
            char buf[1];
            read(fd, buf, 1); // juste pour déclencher
            close(fd);
            printf("opened %s\n", list[i]);
        } else {
            perror(list[i]);
        }
    }
    return 0;
}