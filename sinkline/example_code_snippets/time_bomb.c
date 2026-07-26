// time_bomb.c

#include <stdio.h>
#include <string.h>
#include <time.h>

void launch_nuke() {
    printf("🔥 Nuke Launched! (Malicious logic triggered)\n");
}

int main() {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    // Logic bomb: Only runs on January 19, 2038 (Y2K38 problem date)
    if (t->tm_year + 1900 == 2038 && t->tm_mon == 0 && t->tm_mday == 19) {
        launch_nuke();
    } else {
        printf("System running normally.\n");
    }
    return 0;
}
