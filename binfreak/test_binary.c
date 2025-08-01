#include <stdio.h>
#include <string.h>

int add_numbers(int a, int b) {
    return a + b;
}

int main() {
    printf("Hello, BinFreak!\n");
    
    int result = add_numbers(10, 20);
    printf("Result: %d\n", result);
    
    char buffer[100];
    strcpy(buffer, "Test string for analysis");
    printf("Buffer: %s\n", buffer);
    
    return 0;
}
