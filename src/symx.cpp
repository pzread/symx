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

int main() {
	//Parameter
	int binfd;
	uint8_t *binmap;
	struct stat st;
	uint32_t base = 0x8000;
	uint32_t off = 0x558;

	Context *ctx = new Context;
	cs_insn *insn,*ins;
	size_t idx;
	size_t count;

	binfd = open("./demo",O_RDONLY);
	fstat(binfd,&st);
	binmap = (uint8_t*)mmap(NULL,st.st_size,PROT_READ,MAP_PRIVATE,binfd,0);
	
	cs_open(CS_ARCH_ARM,CS_MODE_THUMB,&ctx->cs);
	count = cs_disasm(
			ctx->cs,
			binmap + off,
			st.st_size - off,
			base + off,
			0,
			&insn);
	for(idx = 0; idx< count; idx++) {
		ins = &insn[idx];
		printf("%s\n",ins->op_str);
	}
	cs_free(insn,count);

	return 0;
}
