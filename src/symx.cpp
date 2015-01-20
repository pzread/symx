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

	auto *ctx = new symx::Context();

	binfd = open("./demo",O_RDONLY);
	
	cs_open(CS_ARCH_ARM,CS_MODE_THUMB,&ctx->cs);
	cs_option(ctx->cs,CS_OPT_DETAIL,1);
	//<main> block emit test
	arm::init(ctx);
	auto probe = new arm::ARMProbe(binfd,-0x8000);
	//arm::emit(ctx,binmap,0x8558,0x558);

	return 0;
}
