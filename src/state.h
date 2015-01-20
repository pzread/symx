#include<memory>

#include"utils.h"
#include"expr.h"
#include"solver.h"

#ifndef _STATE_H_
#define _STATE_H_

class Block;
typedef std::shared_ptr<Block> refBlock;

class State {
	public:
		const unsigned int num_reg;
		const unsigned int num_flag;
		refMem mem;
		refExpr reg[128];
		refCond flag[64];

		State(
			const unsigned int _num_reg,
			const unsigned int _num_flag
		) : num_reg(_num_reg),num_flag(_num_flag) {}
};
class Block : public State {
	public:
		uint64_t start;
		uint64_t end;
		refExpr next_pc;
		Block(
			const unsigned int num_reg,
			const unsigned int num_flag
		) : State(num_reg,num_flag) {}
};

refBlock state_create_block(Context *ctx);

#endif
