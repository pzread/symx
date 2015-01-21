#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<string.h>
#include<unistd.h>
#include<fcntl.h>
#include<sys/stat.h>
#include<sys/mman.h>
#include<capstone/capstone.h>
#include<memory>

#include"utils.h"
#include"context.h"
#include"state.h"
#include"arch/arm/arm.h"

/*
	For quick testing
*/
int main() {
	//Parameter
	int binfd;

	auto *ctx = new arm::ARMContext();

	binfd = open("./demo",O_RDONLY);
	
	//<main> block emit test
	arm::initialize();
	auto probe = ref<arm::ARMProbe>(binfd,-0x8000);
	state_executor(ctx,probe,0x8558);

	return 0;
}
