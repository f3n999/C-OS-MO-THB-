#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    printf("== kmon parameters ==\n");
    printf("Symbol: ");
    fflush(stdout);
    system("cat /sys/module/kmon/parameters/sym 2>/dev/null || echo 'N/A (module not loaded?)'");
    printf("Match: ");
    fflush(stdout);
    system("cat /sys/module/kmon/parameters/match 2>/dev/null || echo 'N/A (module not loaded?)'");
    printf("\n== dmesg (last 20 lines containing 'kmon:') ==\n");
    system("dmesg | grep -F \"kmon:\" | tail -n 20");
    return 0;
}