#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<string.h>
#include<unistd.h>
#include<fcntl.h>
#include<sys/stat.h>
#include<sys/mman.h>
#include<capstone/capstone.h>

#include"context.h"
#include"state.h"
#include"arch/arm/arm.h"

/*
	For quick testing
*/
int main() {
	//Parameter
	int binfd;
	uint8_t *binmap;
	struct stat st;

	Context *ctx = new Context();

	binfd = open("./demo",O_RDONLY);
	fstat(binfd,&st);
	binmap = (uint8_t*)mmap(NULL,st.st_size,PROT_READ,MAP_PRIVATE,binfd,0);
	
	cs_open(CS_ARCH_ARM,CS_MODE_THUMB,&ctx->cs);
	cs_option(ctx->cs,CS_OPT_DETAIL,1);
	//<main> block emit test
	arm_init(ctx);
	arm_emit(ctx,binmap,0x8558,0x558);

	return 0;
}
