#include<stdint.h>
#include<memory>
#include<unordered_set>

#ifndef _EXPR_H_
#define _EXPR_H_

namespace symx {

using namespace symx;

class Context;
class Expr;
class BytMem;
class BytVec;
class Operator;
class Cond;
class ExprVisitor;
class SolvExpr;
class SolvCond;
typedef std::shared_ptr<Expr> refExpr;
typedef std::shared_ptr<BytVec> refBytVec;
typedef std::shared_ptr<BytMem> refBytMem;
typedef std::shared_ptr<Operator> refOperator;
typedef std::shared_ptr<Cond> refCond;
typedef std::shared_ptr<SolvExpr> refSolvExpr;
typedef std::shared_ptr<SolvCond> refSolvCond;

class ExprVisitor {
	public:
		virtual ~ExprVisitor() {};
		virtual int pre_visit(refBytVec vec) = 0;
		virtual int pre_visit(refBytMem mem) = 0;
		virtual int pre_visit(refOperator oper) = 0;
		virtual int pre_visit(refCond cond) = 0;
		virtual int post_visit(refBytVec vec) = 0;
		virtual int post_visit(refBytMem mem) = 0;
		virtual int post_visit(refOperator oper) = 0;
		virtual int post_visit(refCond cond) = 0;
};
class SolvExpr {};
class SolvCond {};

enum ExprType {
	ExprDangle,
	ExprImm,
	ExprVar,
	ExprMem,

	ExprOpStore,
	ExprOpSelect,
	ExprOpExtract,
	ExprOpIte,

	ExprOpAdd,
	ExprOpSub,
	ExprOpMul,
	ExprOpUdiv,
	ExprOpSdiv,
	ExprOpAnd,
	ExprOpOr,
	ExprOpXor,
	ExprOpShl,
	ExprOpLshr,
	ExprOpAshr,
	ExprOpRor,
	ExprOpNeg,
	ExprOpNot,
	ExprOpConcat,
	ExprOpSext,
	ExprOpZext,
};
class Expr : public std::enable_shared_from_this<Expr> {
	public:
		const enum ExprType type;
		const unsigned int size;
		refSolvExpr solver_expr = nullptr;
		Expr(const enum ExprType _type,const unsigned int _size)
			:type(_type),size(_size) {}
		virtual int pre_accept(ExprVisitor *visitor) = 0;
		virtual int post_accept(ExprVisitor *visitor) = 0;
};
class BytVec : public Expr {
	public:
		union {
			const unsigned int id;
			const unsigned int index;
			const uint64_t data;
		};
		BytVec(const refBytVec old)
			: Expr(old->type,old->size),data(old->data) {}
		int pre_accept(ExprVisitor *visitor) {
			return visitor->pre_visit(
				std::static_pointer_cast<BytVec>(
					shared_from_this()));
		}
		int post_accept(ExprVisitor *visitor) {
			return visitor->post_visit(
				std::static_pointer_cast<BytVec>(
					shared_from_this()));
		}
		static refBytVec create_dangle(
			const unsigned int size,
			const unsigned int index
		) {
			return refBytVec(new BytVec(size,index));
		}
		static refBytVec create_imm(
			const unsigned int size,
			const uint64_t imm
		) {
			return refBytVec(new BytVec(size,imm));
		}
		static refBytVec create_var(
			const unsigned int size,
			Context *ctx
		) {
			return refBytVec(new BytVec(size,ctx));
		}
	private:
		BytVec(const unsigned int _size,const unsigned int _index) :
			Expr(ExprDangle,_size),index(_index) {}
		BytVec(const unsigned int _size,const uint64_t imm) :
			Expr(ExprImm,_size),data(imm) {}
		BytVec(const unsigned int _size,Context *ctx);
};
class BytMem : public Expr {
	public:
		union {
			const unsigned int id;
			const unsigned int index;
		};
		BytMem(const refBytMem old)
			: Expr(old->type,old->size),index(old->index) {}
		int pre_accept(ExprVisitor *visitor) {
			return visitor->pre_visit(
				std::static_pointer_cast<BytMem>(
					shared_from_this()));
		}
		int post_accept(ExprVisitor *visitor) {
			return visitor->post_visit(
				std::static_pointer_cast<BytMem>(
					shared_from_this()));
		}
		static refBytMem create_dangle(const unsigned int index) {
			return refBytMem(new BytMem(index));
		}
		static refBytMem create_var(Context *ctx) {
			return refBytMem(new BytMem(ctx));
		}
	private:
		BytMem(const unsigned int _index)
			: Expr(ExprDangle,0),index(_index) {}
		BytMem(Context *ctx);
};
class Operator : public Expr {
	public:
		refExpr operand[3];
		refCond cond;
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
		Operator(
			const unsigned int _size,
			const refCond _cond,
			const refExpr op1,
			const refExpr op2
		) : Expr(ExprOpIte,_size),cond(_cond),op_count(2) {
			operand[0] = op1;
			operand[1] = op2;
		}
		int pre_accept(ExprVisitor *visitor) {
			return visitor->pre_visit(
					std::static_pointer_cast<Operator>(
						shared_from_this()));
		}
		int post_accept(ExprVisitor *visitor) {
			return visitor->post_visit(
				std::static_pointer_cast<Operator>(
					shared_from_this()));
		}
};

enum CondType {
	CondDangle,
	CondIte,
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
		const unsigned int expr_count;
		const unsigned int cond_count;
		unsigned int index;
		refCond cond[3];
		refExpr expr[2];
		refSolvCond solver_cond = nullptr;

		Cond(
			const enum CondType _type,
			const refCond op1
		) : type(_type),expr_count(0),cond_count(1) {
			cond[0] = op1;
		}
		Cond(
			const enum CondType _type,
			const refCond op1,
			const refCond op2
		) : type(_type),expr_count(0),cond_count(2) {
			cond[0] = op1;
			cond[1] = op2;
		}
		Cond(
			const refCond op1,
			const refCond op2,
			const refCond op3
		) : type(CondIte),expr_count(0),cond_count(3) {
			cond[0] = op1;
			cond[1] = op2;
			cond[2] = op3;
		}
		Cond(
			const enum CondType _type,
			const refExpr op1,
			const refExpr op2
		) : type(_type),expr_count(2),cond_count(0) {
			expr[0] = op1;
			expr[1] = op2;
		}
		int pre_accept(ExprVisitor *visitor) {
			return visitor->pre_visit(
					std::static_pointer_cast<Cond>(
						shared_from_this()));
		}
		int post_accept(ExprVisitor *visitor) {
			return visitor->post_visit(
				std::static_pointer_cast<Cond>(
					shared_from_this()));
		}
		static refCond create_dangle(const unsigned int index) {
			return refCond(new Cond(index));
		}
		static refCond create_false() {
			return refCond(new Cond(CondFalse));
		}
		static refCond create_true() {
			return refCond(new Cond(CondTrue));
		}
	private:
		Cond(const unsigned int _index) :
			type(CondDangle),
			expr_count(0),
			cond_count(0),
			index(_index) {}
		Cond(const enum CondType _type) :
			type(_type),expr_count(0),cond_count(0) {}
};

int expr_walk(ExprVisitor *visitor,refExpr expr);
int expr_walk(ExprVisitor *visitor,refCond cond);
template<class refIt>
int expr_iter_walk(ExprVisitor *vis,refIt begin,refIt end) {
	for(auto it = begin; it != end; it++) {
		expr_walk(vis,*it);
	}
	return 0;
}

refExpr expr_store(const refExpr mem,const refExpr idx,const refExpr val);
refExpr expr_select(
	const refExpr mem,
	const refExpr idx,
	const unsigned int size);
refExpr expr_ite(const refCond cond,const refExpr op1,const refExpr op2);
refExpr expr_add(const refExpr op1,const refExpr op2);
refExpr expr_sub(const refExpr op1,const refExpr op2);
refExpr expr_mul(const refExpr op1,const refExpr op2);
refExpr expr_and(const refExpr op1,const refExpr op2);
refExpr expr_or(const refExpr op1,const refExpr op2);
refExpr expr_xor(const refExpr op1,const refExpr op2);
refExpr expr_shl(const refExpr op1,const refExpr op2);
refExpr expr_lshr(const refExpr op1,const refExpr op2);
refExpr expr_ashr(const refExpr op1,const refExpr op2);
refExpr expr_ror(const refExpr op1,const refExpr op2);
refExpr expr_neg(const refExpr op1);
refExpr expr_not(const refExpr op1);
refExpr expr_extract(
	const refExpr op1,
	const unsigned int start,
	const unsigned int end);
//op1 low, op2 high
refExpr expr_concat(const refExpr op1,const refExpr op2);
refExpr expr_sext(const refExpr op1,const unsigned int size);
refExpr expr_zext(const refExpr op1,const unsigned int size);

refCond cond_eq(const refExpr op1,const refExpr op2);
refCond cond_sl(const refExpr op1,const refExpr op2);
refCond cond_sle(const refExpr op1,const refExpr op2);
refCond cond_ul(const refExpr op1,const refExpr op2);
refCond cond_ule(const refExpr op1,const refExpr op2);
refCond cond_sg(const refExpr op1,const refExpr op2);
refCond cond_sge(const refExpr op1,const refExpr op2);
refCond cond_ug(const refExpr op1,const refExpr op2);
refCond cond_uge(const refExpr op1,const refExpr op2);
refCond cond_ite(const refCond cond,const refCond op1,const refCond op2);
refCond cond_and(const refCond op1,const refCond op2);
refCond cond_or(const refCond op1,const refCond op2);
refCond cond_xor(const refCond op1,const refCond op2);
refCond cond_not(const refCond op1);

};

#endif
