#include<stdio.h>
#include<stdlib.h>
#include<string.h>

char *input = (unsigned char*)0x1000;
char *output = (unsigned char*)0x2000;

int get(char *buf,int len) {
    int i = 0;
    while(input[i] != '\0' && i < len) {
	buf[i] = input[i];
	i++;
    }
    buf[i] = '\0';
    return i;
}

int main() {
    char s[100];
    char p[100];

    get(s,20);
    get(p,20);

//out:

    asm("int3");
    return 0;
}
