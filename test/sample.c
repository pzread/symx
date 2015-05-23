#include<stdio.h>
#include<stdlib.h>
#include<string.h>

int main() {
    int off;
    char *input = (char*)0x1000;
    char *output = (char*)0x2000;

    off = 0;
    if(input[0] == 0x30) {
	if(input[1] <= 0x7f) {
	    if(input[2] == 0x2) {
		if(input[3] == 0x0) {
		    off = 4;
		    if(input[off] == 0x4) {
			if(input[off + 1] < 0x23) {
			    memcpy(output,input + off + 2,input[off + 1]);
			}
		    }
		}
	    }
	}
    }

    asm("int3");
    return 0;
}
