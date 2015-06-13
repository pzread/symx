#ifndef _STATE_H_
#define _STATE_H_

#include<unordered_map>
#include<unordered_set>
#include<vector>
#include<memory>
#include<queue>
#include<mutex>
#include<condition_variable>

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
	    std::vector<refBytVec> symbol;

	    unsigned long length;
	    std::vector<uint64_t> path;
	    std::unordered_map<uint64_t,unsigned long> blkmap;

	    State(
		    const ProgCtr &_pc,
		    const refAddrSpace &_as,
		    const refExpr &_mem,
		    const std::vector<refExpr> &_reg,
		    const std::vector<refCond> &_flag)
		: BaseState(_mem,_reg,_flag),pc(_pc),as(_as) {}

	    bool operator<(const State& other) const;
    };
    class Block : public BaseState {
	public:
	    const refCond cond;
	    const refExpr nextpc;

	    Block(
		    const refExpr &_mem,
		    const std::vector<refExpr> &_reg,
		    const std::vector<refCond> &_flag,
		    const refCond &_cond,
		    const refExpr &_nextpc)
		: BaseState(_mem,_reg,_flag),cond(_cond),nextpc(_nextpc) {};
    };
    class BuildVisitor : public ExprVisitor {
	private:
	    Solver *solver;
	    const refState state;
	    std::unordered_map<refExpr,refExpr> expr_map;
	    std::unordered_map<refCond,refCond> cond_map;
	    std::unordered_set<refMemRecord> select_set;

	    refExpr solid_operator(const refOperator &oper);
	    refExpr solid_mem_read(const refOperator &oper);

	public:
	    BuildVisitor(Solver *_solver,const refState &_state)
		: solver(_solver),state(_state) {}
	    refExpr get_expr(const refExpr &expr);
	    refCond get_cond(const refCond &cond);
            const std::unordered_set<refMemRecord>& get_mem_record();
	    int pre_visit(const refBytVec &vec);
	    int pre_visit(const refBytMem &mem);
	    int pre_visit(const refOperator &oper);
	    int pre_visit(const refCond &cond);
	    int post_visit(const refBytVec &vec);
	    int post_visit(const refBytMem &mem);
	    int post_visit(const refOperator &oper);
	    int post_visit(const refCond &cond);
    };

    class ActiveVisitor : public ExprVisitor {
	private:
	    std::unordered_map<refExpr,std::vector<uint64_t>> cache_expr;
	    std::unordered_map<refCond,std::vector<uint64_t>> cache_cond;

	public:
            const std::vector<uint64_t>& get_expr_addr(const refExpr &expr);
            const std::vector<uint64_t>& get_cond_addr(const refCond &cond);
	    int pre_visit(const refBytVec &vec);
	    int pre_visit(const refBytMem &mem);
	    int pre_visit(const refOperator &oper);
	    int pre_visit(const refCond &cond);
	    int post_visit(const refBytVec &vec);
	    int post_visit(const refBytMem &mem);
	    int post_visit(const refOperator &oper);
	    int post_visit(const refCond &cond);
    };
    class ActiveSolver {
	private:
	    Solver *solver;
            ActiveVisitor act_vis;

	public:
	    ActiveSolver(Solver *_solver) : solver(_solver) {}
	    bool solve(
		    const std::unordered_set<refCond> &target_constr,
		    const std::unordered_set<refCond> &constr,
		    std::unordered_map<refExpr,uint64_t> *concrete);
    };

    class ExecutorWorker {
        private:
            Solver *solver;
            ActiveSolver *act_solver;

	    refCond condition_pc(const refExpr &exrpc,const uint64_t rawpc);
            std::vector<refState> solve_state(
                    const refState &cstate,
                    BuildVisitor *build_vis,
		    const refBlock &cblk);
        
        public:
            static int push_work(
                    refState state,
                    std::vector<refBlock> blklist);

            ExecutorWorker() {}
            int loop();
    };
    class Executor {
	private:
	    Context *ctx;
            std::vector<const ExecutorWorker*> worker_list;

            int worker_init();

	public:
	    Executor(Context *_ctx) : ctx(_ctx) {}
	    ~Executor();
	    int execute(uint64_t target_rawpc);
    };
}

#endif
