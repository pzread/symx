#define LOG_PREFIX "expr"

#include<stdint.h>
#include<assert.h>
#include<memory>

#include"context.h"
#include"utils.h"
#include"expr.h"

using namespace symx;

namespace symx {

int expr_walk(ExprVisitor *visitor,refExpr expr) {
	unsigned int i;

	if(expr->pre_accept(visitor) == 0) {
		return 0;
	}
	switch(expr->type) {
	case ExprDangle:
	case ExprImm:
	case ExprVar:
	case ExprMem:
		break;
	case ExprOpIte:
	{
		auto oper = std::static_pointer_cast<Operator>(expr);
		expr_walk(visitor,oper->cond);
		expr_walk(visitor,oper->operand[0]);
		expr_walk(visitor,oper->operand[1]);
		break;
	}
	default:
		auto oper = std::static_pointer_cast<Operator>(expr);
		for(i = 0; i < oper->op_count; i++) {
			expr_walk(visitor,oper->operand[i]);
		}
		break;
	}
	return expr->post_accept(visitor);
}
int expr_walk(ExprVisitor *visitor,refCond cond) {
	unsigned int i;

	if(cond->pre_accept(visitor) == 0){
		return 0;
	}
	switch(cond->type) {
	case CondDangle:
		break;
	default:
		for(i = 0; i < cond->cond_count; i++) {
			expr_walk(visitor,cond->cond[i]);
		}
		for(i = 0; i < cond->expr_count; i++) {
			expr_walk(visitor,cond->expr[i]);
		}
		break;
	}
	return cond->post_accept(visitor);
}

static uint64_t get_next_varid(Context *ctx) {
	ctx->last_var_id += 1;
	return ctx->last_var_id;
}
BytVec::BytVec(const unsigned int _size,Context *ctx) :
	Expr(ExprVar,_size),
	id(get_next_varid(ctx)) {}
BytMem::BytMem(Context *ctx) : Expr(ExprMem,0),id(get_next_varid(ctx)) {}

refExpr expr_store(const refExpr mem,const refExpr idx,const refExpr val) {
	return ref<Operator>(mem,idx,val);
}
refExpr expr_select(
	const refExpr mem,
	const refExpr idx,
	const unsigned int size
) {
	return ref<Operator>(size,mem,idx);
}
refExpr expr_ite(const refCond cond,const refExpr op1,const refExpr op2) {
	assert(op1->size == op2->size);
	return ref<Operator>(op1->size,cond,op1,op2);
}

refExpr expr_add(const refExpr op1,const refExpr op2) {
	assert(op1->size == op2->size);
	return ref<Operator>(ExprOpAdd,op1->size,op1,op2);
}
refExpr expr_sub(const refExpr op1,const refExpr op2) {
	assert(op1->size == op2->size);
	return ref<Operator>(ExprOpSub,op1->size,op1,op2);
}
refExpr expr_mul(const refExpr op1,const refExpr op2) {
	assert(op1->size == op2->size);
	return ref<Operator>(ExprOpMul,op1->size,op1,op2);
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
refCond cond_ite(const refCond cond,const refCond op1,const refCond op2) {
	return ref<Cond>(cond,op1,op2);
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
