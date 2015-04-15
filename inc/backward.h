#include<unordered_set>

#include"utils.h"
#include"expr.h"
#include"context.h"

#ifndef _BACKWARD_H_
#define _BACKWARD_H_

namespace symx {
using namespace symx;

class TargetVisitor : public ExprVisitor {
	public:
		std::unordered_set<refExpr> dyn_expr;
		int pre_visit(const refBytVec &vec);
		int pre_visit(const refBytMem &mem);
		int pre_visit(const refOperator &oper);
		int pre_visit(const refCond &cond);
		int post_visit(const refBytVec &vec);
		int post_visit(const refBytMem &mem);
		int post_visit(const refOperator &oper);
		int post_visit(const refCond &cond);
	private:
		std::unordered_set<refExpr> vis_expr;
};

class Backward {
	public:
		Backward() {}
		int check_point(const refExpr &pc);
};
}

#endif
