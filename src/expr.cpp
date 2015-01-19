#include<stdint.h>
#include<assert.h>
#include<memory>

#include"expr.h"

static uint64_t get_next_varid(Context *ctx) {
	ctx->last_var_id += 1;
	return ctx->last_var_id;
}
BytVec::BytVec(Context *ctx,const unsigned int size):
	Expr(ExprVar,size),
	data(get_next_varid(ctx)) {}


refMem	mem_store(const refMem mem,const refExpr idx,const refExpr val) {
	return std::make_shared<StoreMem>(mem,idx,val);
}
refExpr mem_select(
	const refMem mem,
	const refExpr idx,
	const unsigned int size
) {
	return std::make_shared<SelectMem>(mem,idx,size);
}

refExpr expr_add(const refExpr op1,const refExpr op2) {
	assert(op1->size == op2->size);
	return std::make_shared<Operator>(ExprOpAdd,op1->size,op1,op2);
}
refExpr expr_sub(const refExpr op1,const refExpr op2) {
	assert(op1->size == op2->size);
	return std::make_shared<Operator>(ExprOpSub,op1->size,op1,op2);
}
refCond expr_eq(const refExpr op1,const refExpr op2) {
	return std::make_shared<Cond>(CondEq,op1,op2);
}
