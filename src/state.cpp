#include<memory>

#include"utils.h"
#include"context.h"
#include"expr.h"
#include"state.h"

using namespace symx;

namespace symx {

refBlock state_create_block(Context *ctx) {
	unsigned int i;
	refBlock blk =  ref<Block>();

	blk->mem = BytMem::create_dangle(0);
	for(i = 0; i < ctx->num_reg; i++) {
		blk->reg[i] = BytVec::create_dangle(ctx->reg_size,i);
	}
	for(i = 0;i < ctx->num_flag; i++) {
		blk->flag[i] = Cond::create_false();
	}
	return blk;
}
int state_executor(Context *ctx,Probe *probe,uint64_t pc) {
	while(true) {

	}
	return 0;
}

};
