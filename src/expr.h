#include<stdint.h>
#include<memory>

#include"context.h"

#ifndef _EXPR_H_
#define _EXPR_H_

enum ExprType {
	ExprImm,
	ExprVar,

	ExprOpSelect,
	ExprOpStore,
	
	ExprOpAdd,
	ExprOpSub,
	ExprOpMul,
	ExprOpUdiv,
	ExprOpSdiv,
};
class Expr {
	public:
		const enum ExprType type;
		const unsigned int size;
		Expr(const enum ExprType _type,const unsigned int _size)
			:type(_type),size(_size) {}
};
class BytVec : Expr {
	public:
		uint64_t data;
		BytVec(const unsigned int size,const uint64_t imm) :
			Expr(ExprImm,size),
			data(imm) {}
		BytVec(Context *ctx,const unsigned int size);
};
class Operator : Expr {
	public:
		const unsigned int op_count;
		std::shared_ptr<const Expr> operand[2];

		Operator(
			const enum ExprType op_type,
			const unsigned int size,
			const std::shared_ptr<Expr> op1
		) : Expr(op_type,size),op_count(1) {
			operand[0] = op1;
		}
		Operator(
			const enum ExprType op_type,
			const unsigned int size,
			const std::shared_ptr<Expr> op1,
			const std::shared_ptr<Expr> op2
		) : Expr(op_type,size),op_count(2) {
			operand[0] = op1;
			operand[1] = op2;
		}
};

enum CondType {
	CondEq,
};
class Cond {
	public:
		const enum CondType type;
		const unsigned int op_count;
		std::shared_ptr<const Cond> cond[2];
		std::shared_ptr<const Expr> expr[2];

		Cond(
			const enum CondType _type,
			const std::shared_ptr<Cond> op1
		) : type(_type),op_count(1) {
			cond[0] = op1;
		}
		Cond(
			const enum CondType _type,
			const std::shared_ptr<Cond> op1,
			const std::shared_ptr<Cond> op2
		) : type(_type),op_count(2) {
			cond[0] = op1;
			cond[1] = op2;
		}
		Cond(
			const enum CondType _type,
			const std::shared_ptr<Expr> op1,
			const std::shared_ptr<Expr> op2
		) : type(_type),op_count(2) {
			expr[0] = op1;
			expr[1] = op2;
		}
};

#endif
