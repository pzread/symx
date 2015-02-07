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
class TransVisitor : public symx::ExprVisitor {};
class BuildVisitor : public ExprVisitor {
	public:
		BuildVisitor(const refState _state) : state(_state) {}
		refExpr get_expr(const refExpr expr);
		refCond get_cond(const refCond cond);
		int pre_visit(symx::refBytVec vec);
		int pre_visit(symx::refBytMem mem);
		int pre_visit(symx::refOperator oper);
		int pre_visit(symx::refCond cond);
		int visit(symx::refBytVec vec);
		int visit(symx::refBytMem mem);
		int visit(symx::refOperator oper);
		int visit(symx::refCond cond);
	private:
		const refState state;
		std::unordered_map<refExpr,refExpr> expr_map;
		std::unordered_map<refCond,refCond> cond_map;
};

refBlock state_create_block(Context *ctx);
int state_executor(Context *ctx,refProbe probe,uint64_t pc);

}

#endif
