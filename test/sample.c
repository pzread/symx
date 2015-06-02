#include<stdio.h>
#include<stdlib.h>
#include<string.h>

char *input = (unsigned char*)0x1000;
char *output = (unsigned char*)0x2000;

int get(char *buf,unsigned int off,unsigned int len) {
    unsigned int i = 0;
    while(input[off + i] != '\0' && i < len) {
	buf[i] = input[off + i];
	i++;
    }
    buf[i] = '\0';
    return i;
}
int ru(char *s,char *p) {
    while(*s != '\0') {
	if(*p == '*') {
	    if(ru(s + 1,p)) {
		return 1;
	    }
	} else {
	    if(*s != *p) {
		return 0;
	    }
	    s++;
	}
	p++;
    }
    return (*s) == (*p);
}

int main() {
    char s[100];
    char p[100];

    get(s,0,10);
    get(p,100,10);

    ru(s,p);

//out:

    asm("int3");
    return 0;
}
