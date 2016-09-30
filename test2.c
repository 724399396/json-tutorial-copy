#include <stdio.h>

void main() {   
    printf("%d\n", '"' == '\"');
    char *c = "\"Hello\\nWorld\"";
    while (*c) {
        printf("%d %c\n", *c, *c);
        c++;
    }
    c = "\"\x01\"";
    while (*c) {
        printf("%d %c\n", *c, *c);
        c++;
    }
}
