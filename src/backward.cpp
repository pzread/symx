#define LOG_PREFIX "backward"

#include"utils.h"
#include"expr.h"
#include"backward.h"

using namespace symx;

int TargetVisitor::pre_visit(const refBytVec &vec) {
	if(vis_expr.find(vec) != vis_expr.end()) {
		return 0;
	}
	return 1;
}
int TargetVisitor::pre_visit(const refBytMem &mem) {
	if(vis_expr.find(mem) != vis_expr.end()) {
		return 0;
	}
	return 1;
}
int TargetVisitor::pre_visit(const refOperator &oper) {
	if(oper->type == ExprOpSelect) {
		dyn_expr.insert(oper);
		return 0;
	}
	if(vis_expr.find(oper) != vis_expr.end()) {
		return 0;
	}
	return 1;
}
int TargetVisitor::pre_visit(const refCond &cond) {
	return 0;
}
int TargetVisitor::post_visit(const refBytVec &vec) {
	vis_expr.insert(vec);
	return 1;
}
int TargetVisitor::post_visit(const refBytMem &mem) {
	vis_expr.insert(mem);
	return 1;
}
int TargetVisitor::post_visit(const refOperator &oper) {
	vis_expr.insert(oper);
	return 1;
}
int TargetVisitor::post_visit(const refCond &cond) {
	return 1;
}

int Backward::check_point(const refExpr &pc) {
	TargetVisitor targetvis;

	expr_walk(&targetvis,pc);
	if(targetvis.dyn_expr.size() > 0) {
		dbg("symbolic pc %d\n",targetvis.dyn_expr.size());
	}

	return 0;
}
