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
		BytMem(const unsigned int _id) : Mem(MemDangle),id(_id) {}
		BytMem(Context *ctx);
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
	ExprOpNot,
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
		union {
			const unsigned int id;
			const uint64_t data;
		};
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
class SelectMem : public Expr {
	public:
		const refMem mem;
		const refExpr idx;
		SelectMem(
			const refMem _mem,
			const refExpr _idx,
			const unsigned int _size
		) : Expr(ExprSelect,_size),mem(_mem),idx(_idx) {}
};
class Operator : public Expr {
	public:
		const unsigned int op_count;
		refExpr operand[2];

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
		static refCond create_false(){
			return std::shared_ptr<Cond>(new Cond(CondFalse));
		}
		static refCond create_true(){
			return std::shared_ptr<Cond>(new Cond(CondTrue));
		}
	private:
		Cond(const enum CondType _type) : type(_type),op_count(0) {}
};

refMem expr_store(const refMem mem,const refExpr idx,const refExpr val);
refExpr expr_select(const refMem mem,const refExpr idx,const unsigned int size);
refExpr expr_add(const refExpr op1,const refExpr op2);
refExpr expr_sub(const refExpr op1,const refExpr op2);

refCond cond_eq(const refExpr op1,const refExpr op2);
refCond cond_sl(const refExpr op1,const refExpr op2);
refCond cond_sle(const refExpr op1,const refExpr op2);
refCond cond_ul(const refExpr op1,const refExpr op2);
refCond cond_ule(const refExpr op1,const refExpr op2);
refCond cond_sg(const refExpr op1,const refExpr op2);
refCond cond_sge(const refExpr op1,const refExpr op2);
refCond cond_ug(const refExpr op1,const refExpr op2);
refCond cond_uge(const refExpr op1,const refExpr op2);

#endif
