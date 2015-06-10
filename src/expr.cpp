#define LOG_PREFIX "expr"

#include<stdint.h>
#include<assert.h>
#include<memory>

#include"context.h"
#include"utils.h"
#include"expr.h"

using namespace symx;

namespace symx {
    int ExprVisitor::walk(const refExpr &expr) {
	unsigned int i;

	if(expr->pre_accept(this) == 0) {
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
		auto oper = std::static_pointer_cast<const Operator>(expr);
		walk(oper->cond);
		walk(oper->operand[0]);
		walk(oper->operand[1]);
		break;
	    }
	    default:
		auto oper = std::static_pointer_cast<const Operator>(expr);
		for(i = 0; i < oper->op_count; i++) {
		    walk(oper->operand[i]);
		}
		break;
	}

	return expr->post_accept(this);
    }
    int ExprVisitor::walk(const refCond &cond) {
	unsigned int i;

	if(cond->pre_accept(this) == 0){
	    return 0;
	}
	switch(cond->type) {
	    case CondDangle:
		break;
	    default:
		for(i = 0; i < cond->cond_count; i++) {
		    walk(cond->cond[i]);
		}
		for(i = 0; i < cond->expr_count; i++) {
		    walk(cond->expr[i]);
		}
		break;
	}
	return cond->post_accept(this);
    }

    BytVec::BytVec(const unsigned int _size,Context *ctx)
	: Expr(ExprVar,_size),
	id(ctx->get_next_varid()) {}
    BytMem::BytMem(Context *ctx)
	: Expr(ExprMem,0),id(ctx->get_next_varid()) {}

    refExpr expr_store(
            const refExpr &mem,
            const refExpr &idx,
            const refExpr &val
    ) {
	return ref<Operator>(mem,idx,val);
    }
    refExpr expr_select(
	    const refExpr &mem,
	    const refExpr &idx,
	    const unsigned int size
    ) {
	return ref<Operator>(size,mem,idx);
    }
    refExpr expr_extract(
	    const refExpr &op1,
	    const unsigned int start,
	    const unsigned int end
    ) {
	return ref<Operator>(end - start,op1,start);
    }
    refExpr expr_ite(
            const refCond &cond,
            const refExpr &op1,
            const refExpr &op2
    ) {
	assert(op1->size == op2->size);
	return ref<Operator>(op1->size,cond,op1,op2);
    }

    refExpr expr_add(const refExpr &op1,const refExpr &op2) {
	assert(op1->size == op2->size);
	return ref<Operator>(ExprOpAdd,op1->size,op1,op2);
    }
    refExpr expr_sub(const refExpr &op1,const refExpr &op2) {
	assert(op1->size == op2->size);
	return ref<Operator>(ExprOpSub,op1->size,op1,op2);
    }
    refExpr expr_mul(const refExpr &op1,const refExpr &op2) {
	assert(op1->size == op2->size);
	return ref<Operator>(ExprOpMul,op1->size,op1,op2);
    }
    refExpr expr_and(const refExpr &op1,const refExpr &op2) {
	assert(op1->size == op2->size);
	return ref<Operator>(ExprOpAnd,op1->size,op1,op2);
    }
    refExpr expr_or(const refExpr &op1,const refExpr &op2) {
	assert(op1->size == op2->size);
	return ref<Operator>(ExprOpOr,op1->size,op1,op2);
    }
    refExpr expr_xor(const refExpr &op1,const refExpr &op2) {
	assert(op1->size == op2->size);
	return ref<Operator>(ExprOpXor,op1->size,op1,op2);
    }
    refExpr expr_shl(const refExpr &op1,const refExpr &op2) {
	assert(op1->size == op2->size);
	return ref<Operator>(ExprOpShl,op1->size,op1,op2);
    }
    refExpr expr_lshr(const refExpr &op1,const refExpr &op2) {
	assert(op1->size == op2->size);
	return ref<Operator>(ExprOpLshr,op1->size,op1,op2);
    }
    refExpr expr_ashr(const refExpr &op1,const refExpr &op2) {
	assert(op1->size == op2->size);
	return ref<Operator>(ExprOpAshr,op1->size,op1,op2);
    }
    refExpr expr_ror(const refExpr &op1,const refExpr &op2) {
	assert(op1->size == op2->size);
	return ref<Operator>(ExprOpRor,op1->size,op1,op2);
    }
    refExpr expr_neg(const refExpr &op1) {
	return ref<Operator>(ExprOpNeg,op1->size,op1);
    }
    refExpr expr_not(const refExpr &op1) {
	return ref<Operator>(ExprOpNot,op1->size,op1);
    }
    refExpr expr_concat(const refExpr &op1,const refExpr &op2) {
	return ref<Operator>(ExprOpConcat,op1->size + op2->size,op1,op2);
    }
    refExpr expr_sext(const refExpr &op1,const unsigned int size) {
	assert(op1->size <= size);
	return ref<Operator>(ExprOpSext,size,op1);
    }
    refExpr expr_zext(const refExpr &op1,const unsigned int size) {
	assert(op1->size <= size);
	return ref<Operator>(ExprOpZext,size,op1);
    }

    refCond cond_eq(const refExpr &op1,const refExpr &op2) {
	assert(op1->size == op2->size);
	return ref<Cond>(CondEq,op1,op2);
    }
    refCond cond_sl(const refExpr &op1,const refExpr &op2) {
	assert(op1->size == op2->size);
	return ref<Cond>(CondSl,op1,op2);
    }
    refCond cond_sle(const refExpr &op1,const refExpr &op2) {
	assert(op1->size == op2->size);
	return ref<Cond>(CondSle,op1,op2);
    }
    refCond cond_ul(const refExpr &op1,const refExpr &op2) {
	assert(op1->size == op2->size);
	return ref<Cond>(CondUl,op1,op2);
    }
    refCond cond_ule(const refExpr &op1,const refExpr &op2) {
	assert(op1->size == op2->size);
	return ref<Cond>(CondUle,op1,op2);
    }
    refCond cond_sg(const refExpr &op1,const refExpr &op2) {
	assert(op1->size == op2->size);
	return ref<Cond>(CondSg,op1,op2);
    }
    refCond cond_sge(const refExpr &op1,const refExpr &op2) {
	assert(op1->size == op2->size);
	return ref<Cond>(CondSge,op1,op2);
    }
    refCond cond_ug(const refExpr &op1,const refExpr &op2) {
	assert(op1->size == op2->size);
	return ref<Cond>(CondUg,op1,op2);
    }
    refCond cond_uge(const refExpr &op1,const refExpr &op2) {
	assert(op1->size == op2->size);
	return ref<Cond>(CondUge,op1,op2);
    }
    refCond cond_ite(const refCond &cond,const refCond &op1,const refCond &op2) {
	return ref<Cond>(cond,op1,op2);
    }
    refCond cond_and(const refCond &op1,const refCond &op2) {
	return ref<Cond>(CondAnd,op1,op2);
    }
    refCond cond_or(const refCond &op1,const refCond &op2) {
	return ref<Cond>(CondOr,op1,op2);
    }
    refCond cond_xor(const refCond &op1,const refCond &op2) {
	return ref<Cond>(CondXor,op1,op2);
    }
    refCond cond_not(const refCond &op1) {
	return ref<Cond>(CondNot,op1);
    }

};
