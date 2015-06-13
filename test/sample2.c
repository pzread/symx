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
int cmp(const char *a,const char *b,size_t len) {
    size_t i;
    for(i = 0;i < len;i++) {
        if(a[i] != b[i]) {
            return 1;
        }
    }
    return 0;
}

int main() {
    char s[100];
    char p[100];
    int auth = 0;

    get(s,0,25);
    get(p,100,10);

    if(cmp(s,"AUTH",4) == 0) {
        if(cmp(s + 5,"admin",5) == 0) {
            auth = 1;
        }
    }
    if(auth == 1) {
        ru(s + 15,p);
    }

    asm("int3");
    return 0;
}
