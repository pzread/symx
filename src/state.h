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
		refMem mem;
		refExpr reg[128];
		refCond flag[64];
};
class State : public BaseState {
	public:
		uint64_t pc;
		std::shared_ptr<Probe> probe;
};
class Block : public BaseState {
	public:
		uint64_t start;
		uint64_t end;
		refExpr next_pc;
};

refBlock state_create_block(Context *ctx);
int state_executor(Context *ctx,Probe *probe,uint64_t pc);

}

#endif
