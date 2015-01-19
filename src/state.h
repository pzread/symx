#include<memory>
#include"expr.h"
#include"solver.h"

#ifndef _STATE_H_
#define _STATE_H_

class State {
	public:
		const unsigned int num_reg;
		const unsigned int num_flag;
		refMem mem;
		refExpr reg[64];
		refCond flag[64];

		State(
			const unsigned int _num_reg,
			const unsigned int _num_flag
		) : num_reg(_num_reg),num_flag(_num_flag) {}
};
class Block : public State {
	public:
		Block(
			const unsigned int num_reg,
			const unsigned int num_flag
		) : State(num_reg,num_flag) {}
};

Block state_create_block(Context *ctx);

#endif
