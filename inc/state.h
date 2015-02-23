#include<memory>
#include<unordered_map>
#include<unordered_set>
#include<bitset>
#include<map>
#include<vector>
#include<string>

#include"utils.h"
#include"expr.h"
#include"context.h"

#ifndef _STATE_H_
#define _STATE_H_

namespace symx {

using namespace symx;

class MemRecord;
class Block;
class State;
typedef std::shared_ptr<MemRecord> refMemRecord;
typedef std::shared_ptr<Block> refBlock;
typedef std::shared_ptr<State> refState;

class MemPage : public std::enable_shared_from_this<MemPage> {
	public:
		const uint64_t start;
		const unsigned int prot;
		std::bitset<PAGE_SIZE> dirty;
		MemPage(const uint64_t _start,const unsigned int _prot)
			: start(_start),prot(_prot) {}
};
class MemRecord : public std::enable_shared_from_this<MemRecord> {
	public:
		const refOperator oper;
		const refExpr mem;
		const refExpr idx;
		const unsigned int size;
		MemRecord(
			const refOperator _oper,
			const refExpr _mem,
			const refExpr _idx,
			const unsigned int _size
		) : oper(_oper),mem(_mem),idx(_idx),size(_size) {}
};
class AddrSpace {
	public:
		std::vector<std::pair<uint64_t,refBytVec>> mem_symbol;
		std::unordered_set<refCond> mem_constraint;
		AddrSpace(Context *ctx,const refProbe &_probe);
		refExpr get_mem() const;
		int handle_select(const uint64_t idx,const unsigned int size);
	private:
		const refProbe probe;
		Context *ctx;
		refExpr mem;
		std::map<uint64_t,MemPage> page_map;
};
class BaseState : public std::enable_shared_from_this<BaseState> {
	public:
		refExpr mem;
		refExpr reg[256];
		refCond flag[64];
};
class State : public BaseState {
	public:
		const ProgCtr pc;
		const refProbe probe;
		std::vector<refBytVec> symbol;
		std::unordered_set<refCond> constraint;
		std::unordered_set<refMemRecord> select_record;
		State(const ProgCtr &_pc,const refProbe &_probe)
			: pc(_pc),probe(_probe) {}
};
class Block : public BaseState {
	public:
		const ProgCtr pc;
		refExpr next_insmd;
		std::vector<std::string> discode;
		Block(const ProgCtr _pc) : pc(_pc) {};
};
class BuildVisitor : public ExprVisitor {
	public:
		BuildVisitor(const refState &_state) : state(_state) {}
		refExpr get_expr(const refExpr expr);
		refCond get_cond(const refCond cond);
		int get_mem_record(
			std::unordered_set<refMemRecord> *selrec);
		int pre_visit(const refBytVec &vec);
		int pre_visit(const refBytMem &mem);
		int pre_visit(const refOperator &oper);
		int pre_visit(const refCond &cond);
		int post_visit(const refBytVec &vec);
		int post_visit(const refBytMem &mem);
		int post_visit(const refOperator &oper);
		int post_visit(const refCond &cond);
	private:
		const refState state;
		std::unordered_map<refExpr,refExpr> expr_map;
		std::unordered_map<refCond,refCond> cond_map;
		std::unordered_set<refMemRecord> select_record;
};
class TransVisitor : public ExprVisitor {};

refBlock state_create_block(Context *ctx,const ProgCtr &pc);
int state_executor(
	Context *ctx,
	const refProbe &probe,
	const uint64_t entry_rawpc);

}

#endif
