#include<stdint.h>
#include<memory>

#include"utils.h"
#include"context.h"

#ifndef _EXPR_H_
#define _EXPR_H_

namespace symx {

using namespace symx;

class Expr;
class BytMem;
class BytVec;
class Operator;
class Cond;
class ExprVisitor;
typedef std::shared_ptr<Expr> refExpr;
typedef std::shared_ptr<BytVec> refBytVec;
typedef std::shared_ptr<BytMem> refBytMem;
typedef std::shared_ptr<Operator> refOperator;
typedef std::shared_ptr<Cond> refCond;

class ExprVisitor {
	public:
		virtual ~ExprVisitor() {}
		virtual int visit(refBytVec vec) = 0;
		virtual int visit(refBytMem mem) = 0;
		virtual int visit(refOperator oper) = 0;
		virtual int visit(refCond cond) = 0;
};

enum ExprType {
	ExprDangle,
	ExprMem,
	ExprImm,
	ExprVar,

	ExprOpStore,
	ExprOpSelect,
	ExprOpExtract,

	ExprOpAdd,
	ExprOpSub,
	ExprOpMul,
	ExprOpUdiv,
	ExprOpSdiv,
	ExprOpNeg,
	ExprOpNot,
	ExprOpConcat,
};
class Expr : public std::enable_shared_from_this<Expr> {
	public:
		const enum ExprType type;
		const unsigned int size;
		Expr(const enum ExprType _type,const unsigned int _size)
			:type(_type),size(_size) {}
		virtual int accept(ExprVisitor *visitor) = 0;
};
class BytVec : public Expr {
	public:
		union {
			const unsigned int id;
			const uint64_t data;
		};
		int accept(ExprVisitor *visitor) {
			return visitor->visit(
					std::static_pointer_cast<BytVec>(
						shared_from_this()));
		}
		static std::shared_ptr<BytVec> create_dangle(
			const unsigned int _size,
			const unsigned int _id
		) {
			return std::shared_ptr<BytVec>(new BytVec(_size,_id));
		}
		static std::shared_ptr<BytVec> create_imm(
			const unsigned int _size,
			const uint64_t imm
		) {
			return std::shared_ptr<BytVec>(new BytVec(_size,imm));
		}
		static std::shared_ptr<BytVec> create_var(
			const unsigned int _size,
			Context *ctx
		) {
			return std::shared_ptr<BytVec>(new BytVec(_size,ctx));
		}
	private:
		BytVec(const unsigned int _size,const unsigned int _id) :
			Expr(ExprDangle,_size),id(_id) {}
		BytVec(const unsigned int _size,const uint64_t imm) :
			Expr(ExprImm,_size),data(imm) {}
		BytVec(const unsigned int _size,Context *ctx);
};
class BytMem : public Expr {
	public:
		const unsigned int id;
		int accept(ExprVisitor *visitor) {
			return visitor->visit(
					std::static_pointer_cast<BytMem>(
						shared_from_this()));
		}
		static std::shared_ptr<BytMem> create_dangle(
			const unsigned int _id		
		) {
			return std::shared_ptr<BytMem>(new BytMem(_id));
		}
		static std::shared_ptr<BytMem> create_var(
			Context *ctx
		) {
			return std::shared_ptr<BytMem>(new BytMem(ctx));
		}
	private:
		BytMem(const unsigned int _id) : Expr(ExprDangle,0),id(_id) {}
		BytMem(Context *ctx);
};
class Operator : public Expr {
	public:
		refExpr operand[3];
		unsigned int start;
		const unsigned int op_count;

		Operator(
			const enum ExprType op_type,
			const unsigned int _size,
			const refExpr op1
		) : Expr(op_type,_size),op_count(1) {
			operand[0] = op1;
		}
		Operator(
			const enum ExprType op_type,
			const unsigned int _size,
			const refExpr op1,
			const refExpr op2
		) : Expr(op_type,_size),op_count(2) {
			operand[0] = op1;
			operand[1] = op2;
		}
		Operator(
			const refExpr mem,
			const refExpr idx,
			const refExpr val
		) : Expr(ExprOpStore,0),op_count(3) {
			operand[0] = mem;
			operand[1] = idx;
			operand[2] = val;
		}
		Operator(
			const unsigned int _size,
			const refExpr mem,
			const refExpr idx
		) : Expr(ExprOpSelect,_size),op_count(2) {
			operand[0] = mem;
			operand[1] = idx;
		}
		Operator(
			const unsigned int _size,
			const refExpr op1,
			const unsigned int _start
		) : Expr(ExprOpExtract,_size),start(_start),op_count(1) {
			operand[0] = op1;
		}
		int accept(ExprVisitor *visitor) {
			return visitor->visit(
					std::static_pointer_cast<Operator>(
						shared_from_this()));
		}
};

enum CondType {
	CondFalse,
	CondTrue,
	CondEq,
	CondSl,
	CondSle,
	CondUl,
	CondUle,
	CondSg,
	CondSge,
	CondUg,
	CondUge,
	CondAnd,
	CondOr,
	CondXor,
	CondNot,
};
class Cond : public std::enable_shared_from_this<Cond> {
	public:
		const enum CondType type;
		const unsigned int cond_count;
		const unsigned int expr_count;
		refCond cond[2];
		refExpr expr[2];

		Cond(
			const enum CondType _type,
			const refCond op1
		) : type(_type),cond_count(0),expr_count(1) {
			cond[0] = op1;
		}
		Cond(
			const enum CondType _type,
			const refCond op1,
			const refCond op2
		) : type(_type),cond_count(0),expr_count(2) {
			cond[0] = op1;
			cond[1] = op2;
		}
		Cond(
			const enum CondType _type,
			const refExpr op1,
			const refExpr op2
		) : type(_type),cond_count(2),expr_count(0) {
			expr[0] = op1;
			expr[1] = op2;
		}
		int accept(ExprVisitor *visitor) {
			return visitor->visit(
					std::static_pointer_cast<Cond>(
						shared_from_this()));
		}
		static refCond create_false(){
			return std::shared_ptr<Cond>(new Cond(CondFalse));
		}
		static refCond create_true(){
			return std::shared_ptr<Cond>(new Cond(CondTrue));
		}
	private:
		Cond(const enum CondType _type) :
			type(_type),cond_count(0),expr_count(0) {}
};

int expr_walk(ExprVisitor *visitor,refExpr expr);
int expr_walk(ExprVisitor *visitor,refCond cond);

refExpr expr_store(const refExpr mem,const refExpr idx,const refExpr val);
refExpr expr_select(const refExpr mem,const refExpr idx,const unsigned int size);
refExpr expr_add(const refExpr op1,const refExpr op2);
refExpr expr_sub(const refExpr op1,const refExpr op2);
refExpr expr_neg(const refExpr op1);
refExpr expr_not(const refExpr op1);
refExpr expr_extract(
	const refExpr op1,
	const unsigned int start,
	const unsigned int end);
refExpr expr_concat(const refExpr op1,const refExpr op2);

refCond cond_eq(const refExpr op1,const refExpr op2);
refCond cond_sl(const refExpr op1,const refExpr op2);
refCond cond_sle(const refExpr op1,const refExpr op2);
refCond cond_ul(const refExpr op1,const refExpr op2);
refCond cond_ule(const refExpr op1,const refExpr op2);
refCond cond_sg(const refExpr op1,const refExpr op2);
refCond cond_sge(const refExpr op1,const refExpr op2);
refCond cond_ug(const refExpr op1,const refExpr op2);
refCond cond_uge(const refExpr op1,const refExpr op2);
refCond cond_and(const refCond op1,const refCond op2);
refCond cond_or(const refCond op1,const refCond op2);
refCond cond_xor(const refCond op1,const refCond op2);
refCond cond_not(const refCond op1);

};

#endif
