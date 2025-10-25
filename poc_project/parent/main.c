#include <stdio.h>

void secret_function() {
    printf("This is a secret function, decrypted and running!\n");
}

int main() {
    printf("Parent process started.\n");
    secret_function();
    printf("Parent process exiting.\n");
    return 0;
}
