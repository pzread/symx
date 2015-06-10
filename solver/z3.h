#ifndef LOG_PREFIX
#define LOG_PREFIX "z3_solver"
#endif

#include<z3.h>
#include<memory>
#include<unordered_map>
#include<unordered_set>
#include"utils.h"
#include"context.h"
#include"expr.h"
#include"state.h"

#ifndef _SOLVER_H_
#define _SOLVER_H_

namespace z3_solver {
class Z3Solver;
class Z3SolvExpr;
class Z3SolvCond;
typedef std::shared_ptr<const Z3SolvExpr> refZ3SolvExpr;
typedef std::shared_ptr<const Z3SolvCond> refZ3SolvCond;

class Z3SolvExpr {
	public:
		Z3_context context;
		Z3_ast ast;
		Z3SolvExpr(Z3_context _context,Z3_ast _ast);
		~Z3SolvExpr();
};
class Z3SolvCond {
	public:
		Z3_context context;
		Z3_ast ast;
		Z3SolvCond(Z3_context _context,Z3_ast _ast);
		~Z3SolvCond();
};

class Z3TransVisitor : public symx::ExprVisitor {
	private:
		const Z3Solver *solver;
                std::unordered_map<symx::refExpr,refZ3SolvExpr> cache_expr;
                std::unordered_map<symx::refCond,refZ3SolvCond> cache_cond;

		Z3_sort bvsort1;
		Z3_sort bvsort4;
		Z3_ast bvimm41;
		Z3_params simplify_param;

	public:
		Z3TransVisitor(const Z3Solver *_solver);
		Z3_ast expr_to_ast(const symx::refExpr &expr);
		Z3_ast cond_to_ast(const symx::refCond &cond);
		int pre_visit(const symx::refBytVec &vec);
		int pre_visit(const symx::refBytMem &mem);
		int pre_visit(const symx::refOperator &oper);
		int pre_visit(const symx::refCond &cond);
		int post_visit(const symx::refBytVec &vec);
		int post_visit(const symx::refBytMem &mem);
		int post_visit(const symx::refOperator &oper);
		int post_visit(const symx::refCond &cond);
};
class Z3Solver : public symx::Solver {
	private:
	        Z3TransVisitor *trans_vis;

		static void error_handler(Z3_context ctx,Z3_error_code error) {
			err("Z3 Solver: %s\n",
				Z3_get_error_msg_ex(ctx,error));
		}

	public:
		Z3_context context;
		Z3_solver solver;

		Z3Solver();
		~Z3Solver();
		bool solve(
			const std::unordered_set<symx::refCond> &cons,
			std::unordered_map<symx::refExpr,uint64_t> *var);
};

}

#endif
