#include<memory>

#include"utils.h"
#include"expr.h"

#ifndef _STATE_H_
#define _STATE_H_

namespace symx {

using namespace symx;

class Block;
class State;
class Probe;
typedef std::shared_ptr<Block> refBlock;
typedef std::shared_ptr<State> refState;

class BaseState {
	public:
		refExpr mem;
		refExpr reg[128];
		refCond flag[64];
};
class State : public BaseState {
	public:
		uint64_t pc;
		refProbe probe;
		State(const uint64_t _pc,refProbe _probe) :
			pc(_pc),probe(_probe) {}
};
class Block : public BaseState {
	public:
		uint64_t start;
		uint64_t end;
		refExpr next_pc;
};

refBlock state_create_block(Context *ctx);
int state_executor(Context *ctx,refProbe probe,uint64_t pc);

}

#endif
