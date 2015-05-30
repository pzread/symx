#ifndef _STATE_H_
#define _STATE_H_

#include<unordered_map>
#include<unordered_set>
#include<vector>
#include<memory>
#include<queue>

#include"utils.h"
#include"expr.h"
#include"vm.h"

namespace symx {
    using namespace symx;

    class ProgCtr {
	public:
	    const uint64_t rawpc;
	    const int mode;
	    ProgCtr(const uint64_t _rawpc,const int _mode)
		: rawpc(_rawpc),mode(_mode) {}
	    bool operator==(const ProgCtr &other) const {
		return rawpc == other.rawpc && mode == other.mode;
	    }
    };
}
namespace std {
    template<> struct hash<symx::ProgCtr> {
	std::size_t operator()(const symx::ProgCtr &key) const {
	    return (key.rawpc << 8) | key.mode;
	}
    };
}
namespace symx {
    class BaseState : public std::enable_shared_from_this<BaseState> {
	public:
	    const refExpr mem;
	    const std::vector<refExpr> reg;
	    const std::vector<refCond> flag;

	    BaseState(
		    const refExpr &_mem,
		    const std::vector<refExpr> _reg,
		    const std::vector<refCond> _flag)
		: mem(_mem),reg(_reg),flag(_flag) {}
    };
    class State : public BaseState {
	public:
	    const ProgCtr pc;
	    const refAddrSpace as;
	    std::unordered_set<refCond> constr;
	    std::unordered_set<refMemRecord> select_set;
	    std::vector<refMemRecord> store_seq;
	    std::vector<refBytVec> symbol;

	    std::vector<refBlock> path;

	    State(
		    const ProgCtr &_pc,
		    const refAddrSpace &_as,
		    const refExpr &_mem,
		    const std::vector<refExpr> &_reg,
		    const std::vector<refCond> &_flag
		 ) : BaseState(_mem,_reg,_flag),pc(_pc),as(_as) {}
    };
    class Block : public BaseState {
	public:
	    const refCond cond;
	    const refExpr nextpc;
	    int length;

	    Block(
		    const refExpr &_mem,
		    const std::vector<refExpr> &_reg,
		    const std::vector<refCond> &_flag,
		    const refCond &_cond,
		    const refExpr &_nextpc
		 ) : BaseState(_mem,_reg,_flag),cond(_cond),nextpc(_nextpc),length(0) {};

	    bool operator<(const Block& other) const;
    };
    class BuildVisitor : public ExprVisitor {
	private:
	    Solver *solver;
	    const refState state;
	    std::unordered_map<refExpr,refExpr> expr_map;
	    std::unordered_map<refCond,refCond> cond_map;
	    std::unordered_set<refMemRecord> select_set;
	    std::vector<refMemRecord> store_seq;

	    refExpr solid_operator(const refOperator &oper);

	public:
	    BuildVisitor(Solver *_solver,const refState &_state)
		: solver(_solver),state(_state) {}
	    refExpr get_expr(const refExpr &expr);
	    refCond get_cond(const refCond &cond);
	    int get_mem_record(
		    std::unordered_set<refMemRecord> *selset,
		    std::vector<refMemRecord> *strseq);
	    int pre_visit(const refBytVec &vec);
	    int pre_visit(const refBytMem &mem);
	    int pre_visit(const refOperator &oper);
	    int pre_visit(const refCond &cond);
	    int post_visit(const refBytVec &vec);
	    int post_visit(const refBytMem &mem);
	    int post_visit(const refOperator &oper);
	    int post_visit(const refCond &cond);
    };
    class Executor {
	private:
	    Context *ctx;

	    refCond condition_pc(const refExpr &exrpc,const uint64_t rawpc);
	    std::vector<refState> solve_state(
		    const refState cstate,
		    BuildVisitor *build_vis,
		    const refBlock cblk);

	public:
	    Executor(Context *_ctx) : ctx(_ctx) {}
	    ~Executor();
	    int execute();
    };
    /*
    class SolidFixVisitor : public ExprVisitor {
	private:
	    Solver *solver;
	    const refState state;
	    std::unordered_set<refExpr> visited;

	public:
	    SolidFixVisitor(Solver *_solver,const refState &_state)
		: solver(_solver),state(_state) {}

	    bool get_fix(const refExpr &expr);
	    int pre_visit(const refBytVec &vec);
	    int pre_visit(const refBytMem &mem);
	    int pre_visit(const refOperator &oper);
	    int pre_visit(const refCond &cond);
	    int post_visit(const refBytVec &vec);
	    int post_visit(const refBytMem &mem);
	    int post_visit(const refOperator &oper);
	    int post_visit(const refCond &cond);
    };
    */
}

#endif
