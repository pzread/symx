#include<memory>

#include"utils.h"
#include"expr.h"
#include"context.h"

#ifndef _STATE_H_
#define _STATE_H_

namespace symx {

using namespace symx;

class Block;
class State;
typedef std::shared_ptr<Block> refBlock;
typedef std::shared_ptr<State> refState;

class BaseState {
	public:
		refExpr mem;
		refExpr reg[256];
		refCond flag[64];
};
class State : public BaseState {
	public:
		uint64_t pc;
		refProbe probe;
		refSolverExpr solver_mem;
		refSolverExpr solver_reg[256];
		refSolverCond solver_flag[64];
		std::vector<refCond> constraint;
		State(const uint64_t _pc,refProbe _probe)
			: pc(_pc),probe(_probe) {}
};
class Block : public BaseState {
	public:
		uint64_t start;
		uint64_t end;
		refExpr next_pc;
};
class TransVisitor : public symx::ExprVisitor {
	public:
		virtual refSolverExpr get_solverexpr(const refExpr expr) = 0;
		virtual refSolverCond get_solvercond(const refCond cond) = 0;
};

refBlock state_create_block(Context *ctx);
int state_executor(Context *ctx,refProbe probe,uint64_t pc);

}

#endif
