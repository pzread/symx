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
int state_executor(Context *ctx,refProbe probe,uint64_t pc) {
	unsigned int i;
	refState nstate,cstate;
	refBlock cblk;
	
	nstate = ref<State>(pc,probe);
	nstate->mem = BytMem::create_var(ctx);
	for(i = 0; i < ctx->num_reg; i++) {
		nstate->reg[i] = BytVec::create_imm(
			ctx->reg_size,
			probe->read_reg(i));
	}
	for(i = 0; i < ctx->num_flag; i++) {
		if(probe->read_flag(i)) {
			nstate->flag[i] = Cond::create_true();
		} else {
			nstate->flag[i] = Cond::create_false();
		}
	}
	ctx->state.push(nstate);

	while(!ctx->state.empty()) {
		cstate = ctx->state.front();
		ctx->state.pop();

		auto blk_it = ctx->block.find(pc);
		if(blk_it == ctx->block.end()) {
			cblk = ctx->interpret(probe,pc);
		} else {
			cblk = blk_it->second;
		}
		break;
	}
	return 0;
}

};
