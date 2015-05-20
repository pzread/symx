#include<stdio.h>
#include<stdlib.h>
#include<string.h>

int main() {
    char *input = (char*)0x1000;
    char *output = (char*)0x2000;

    if(input[0] == 10) {
	output[0] = 20;
    } else {
	output[0] = 30;
    }

    asm("int3");
    return 0;
}
