#include<stdio.h>
#include<stdlib.h>
#include<string.h>

char *input = (unsigned char*)0x1000;
char *output = (unsigned char*)0x2000;
char buf[100] = {0};
char store[100] = {0};

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
    char *ptr,*end;
    int type;
    unsigned int len;
    int auth = 0;

    //fgets(buf,30,stdin);
    get(buf,0,30);
    ptr = buf;
    while(*ptr) {
        /*if(strncmp(ptr,"AUTH",4) == 0) {
            type = 1;
        } else if(strncmp(ptr,"SERH",4) == 0) {
            type = 2;
        } else if(strncmp(ptr,"STOR",4) == 0) {
            type = 3;
        } else {
            type = 0;
        }*/
        if(*ptr == 'A') {
            type = 1;
        } else if(*ptr == 'S') {
            type = 2;
        } else if(*ptr == 'T') {
            type = 3;
        } else {
            type = 0;
        }
        ptr += 1;
        end = strstr(ptr,"|");
        if(end == NULL) {
            goto out;
        }
        /*end = ptr;
        while(*end != '\0' && *end != '|') {
            end++;
        }
        if(*end != '|') {
            goto out;
        }*/
        len = end - ptr;
        *end = '\0';

        if(*ptr == '\0') {
            goto out;
        }

        switch(type) {
            case 1:
                if(len > 5) {
                    goto out;
                }
                if(strcmp(ptr,"admin") == 0) {
                    auth = 1;
                }
                break;
            case 2:
                if(len > 4) {
                    goto out;
                }
                ru(store,ptr);
                break;
            case 3:
                if(auth != 1) {
                    goto out;
                }
                if(len > 10) {
                    goto out;
                }
                strncpy(store,ptr,10);
                store[10] = '\0';
                break;
            default:
                goto out;
                break;
        }
        
        ptr += (len + 1);
    }

out:

    asm("int3");
    return 0;
}
