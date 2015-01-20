#include<stdint.h>
#include<assert.h>
#include<memory>

#include"utils.h"
#include"expr.h"

using namespace symx;

namespace symx {

static uint64_t get_next_varid(Context *ctx) {
	ctx->last_var_id += 1;
	return ctx->last_var_id;
}
BytMem::BytMem(Context *ctx) : Mem(MemVar),id(get_next_varid(ctx)) {}
BytVec::BytVec(const unsigned int _size,Context *ctx) :
	Expr(ExprVar,size),
	id(get_next_varid(ctx)) {}

refMem expr_store(const refMem mem,const refExpr idx,const refExpr val) {
	return ref<StoreMem>(mem,idx,val);
}
refExpr expr_select(
	const refMem mem,
	const refExpr idx,
	const unsigned int size
) {
	return ref<SelectMem>(mem,idx,size);
}
refExpr expr_add(const refExpr op1,const refExpr op2) {
	assert(op1->size == op2->size);
	return ref<Operator>(ExprOpAdd,op1->size,op1,op2);
}
refExpr expr_sub(const refExpr op1,const refExpr op2) {
	assert(op1->size == op2->size);
	return ref<Operator>(ExprOpSub,op1->size,op1,op2);
}
refExpr expr_neg(const refExpr op1) {
	return ref<Operator>(ExprOpNeg,op1->size,op1);
}
refExpr expr_not(const refExpr op1) {
	return ref<Operator>(ExprOpNot,op1->size,op1);
}
refExpr expr_extract(
	const refExpr op1,
	const unsigned int start,
	const unsigned int end
) {
	return ref<Operator>(end - start,op1,start);
}
refExpr expr_concat(const refExpr op1,const refExpr op2) {
	return ref<Operator>(ExprOpConcat,op1->size + op2->size,op1,op2);
}

refCond cond_eq(const refExpr op1,const refExpr op2) {
	assert(op1->size == op2->size);
	return ref<Cond>(CondEq,op1,op2);
}
refCond cond_sl(const refExpr op1,const refExpr op2) {
	assert(op1->size == op2->size);
	return ref<Cond>(CondSl,op1,op2);
}
refCond cond_sle(const refExpr op1,const refExpr op2) {
	assert(op1->size == op2->size);
	return ref<Cond>(CondSle,op1,op2);
}
refCond cond_ul(const refExpr op1,const refExpr op2) {
	assert(op1->size == op2->size);
	return ref<Cond>(CondUl,op1,op2);
}
refCond cond_ule(const refExpr op1,const refExpr op2) {
	assert(op1->size == op2->size);
	return ref<Cond>(CondUle,op1,op2);
}
refCond cond_sg(const refExpr op1,const refExpr op2) {
	assert(op1->size == op2->size);
	return ref<Cond>(CondSg,op1,op2);
}
refCond cond_sge(const refExpr op1,const refExpr op2) {
	assert(op1->size == op2->size);
	return ref<Cond>(CondSge,op1,op2);
}
refCond cond_ug(const refExpr op1,const refExpr op2) {
	assert(op1->size == op2->size);
	return ref<Cond>(CondUg,op1,op2);
}
refCond cond_uge(const refExpr op1,const refExpr op2) {
	assert(op1->size == op2->size);
	return ref<Cond>(CondUge,op1,op2);
}
refCond cond_and(const refCond op1,const refCond op2) {
	return ref<Cond>(CondAnd,op1,op2);
}
refCond cond_or(const refCond op1,const refCond op2) {
	return ref<Cond>(CondOr,op1,op2);
}
refCond cond_xor(const refCond op1,const refCond op2) {
	return ref<Cond>(CondXor,op1,op2);
}
refCond cond_not(const refCond op1) {
	return ref<Cond>(CondNot,op1);
}

};
