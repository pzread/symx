#include<stdint.h>
#include<memory>

#include"context.h"

#ifndef _EXPR_H_
#define _EXPR_H_

class Mem;
class Expr;
class Cond;
typedef std::shared_ptr<Mem> refMem;
typedef std::shared_ptr<Expr> refExpr;
typedef std::shared_ptr<Cond> refCond;

enum MemType {
	MemDangle,
	MemVar,
	MemStore,
};
class Mem {
	public:
		const enum MemType type;
		Mem(const enum MemType _type) : type(_type) {}
};
class BytMem : public Mem {
	public:
		const unsigned int id;
		BytMem() : Mem(MemDangle),id(0) {}
		BytMem(const unsigned short _id) : Mem(MemVar),id(_id) {}
};
class StoreMem : public Mem {
	public:
		const refMem mem;
		const refExpr idx;
		const refExpr val;
		StoreMem(
			const refMem _mem,
			const refExpr _idx,
			const refExpr _val
		) : Mem(MemStore),mem(_mem),idx(_idx),val(_val) {}
};

enum ExprType {
	ExprDangle,
	ExprImm,
	ExprVar,
	ExprSelect,

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
class BytVec : public Expr {
	public:
		const uint64_t data;
		BytVec(const unsigned int size,const unsigned short id) :
			Expr(ExprDangle,size),data(id) {}
		BytVec(const unsigned int size,const uint64_t imm) :
			Expr(ExprImm,size),data(imm) {}
		BytVec(Context *ctx,const unsigned int size);
};
class SelectMem : public Expr {
	public:
		const refMem mem;
		const refExpr idx;
		SelectMem(
			const refMem _mem,
			const refExpr _idx,
			const unsigned int size
		) : Expr(ExprSelect,size),mem(_mem),idx(_idx) {}
};
class Operator : public Expr {
	public:
		const unsigned int op_count;
		refExpr operand[2];

		Operator(
			const enum ExprType op_type,
			const unsigned int size,
			const refExpr op1
		) : Expr(op_type,size),op_count(1) {
			operand[0] = op1;
		}
		Operator(
			const enum ExprType op_type,
			const unsigned int size,
			const refExpr op1,
			const refExpr op2
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
		refCond cond[2];
		refExpr expr[2];

		Cond(
			const enum CondType _type,
			const refCond op1
		) : type(_type),op_count(1) {
			cond[0] = op1;
		}
		Cond(
			const enum CondType _type,
			const refCond op1,
			const refCond op2
		) : type(_type),op_count(2) {
			cond[0] = op1;
			cond[1] = op2;
		}
		Cond(
			const enum CondType _type,
			const refExpr op1,
			const refExpr op2
		) : type(_type),op_count(2) {
			expr[0] = op1;
			expr[1] = op2;
		}
};

refExpr expr_add(const refExpr op1,const refExpr op2);
refExpr expr_sub(const refExpr op1,const refExpr op2);
refCond expr_eq(const refExpr op1,const refExpr op2);

#endif
