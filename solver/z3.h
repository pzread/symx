#include<z3.h>
#include<memory>
#include<unordered_map>
#include"utils.h"
#include"context.h"
#include"expr.h"
#include"state.h"

#ifndef _SOLVER_H_
#define _SOLVER_H_

#ifndef LOG_PREFIX
#define LOG_PREFIX "z3_solver"
#endif

namespace z3_solver {
	class Z3Solver;
	class Z3SolverExpr;
	class Z3SolverCond;
	typedef std::shared_ptr<Z3SolverExpr> refZ3SolverExpr;
	typedef std::shared_ptr<Z3SolverCond> refZ3SolverCond;

	class Z3TransVisitor : public symx::TransVisitor {
		public:
			Z3TransVisitor(
				const Z3Solver *_solver,
				const symx::refSolverExpr mem,
				const std::unordered_map
					<unsigned int,symx::refSolverExpr> &reg,
				const std::unordered_map
					<unsigned int,symx::refSolverCond> &flag
			);
			~Z3TransVisitor();
			symx::refSolverExpr get_solver_expr(
					const symx::refExpr expr);
			symx::refSolverCond get_solver_cond(
					const symx::refCond cond);
			int visit(symx::refBytVec vec);
			int visit(symx::refBytMem mem);
			int visit(symx::refOperator oper);
			int visit(symx::refCond cond);

		private:
			const Z3Solver *solver;
			const symx::refSolverExpr dangle_mem;
			const std::unordered_map
				<unsigned int,symx::refSolverExpr> &dangle_reg;
			const std::unordered_map
				<unsigned int,symx::refSolverCond> &dangle_flag;
			Z3_sort bvsort1;
			Z3_sort bvsort4;
			std::unordered_map<symx::refExpr,Z3_ast> expr_ast;
			std::unordered_map<symx::refCond,Z3_ast> cond_ast;
	};
	class Z3Solver : public symx::Solver {
		public:
			Z3_context context;
			Z3_solver solver;

			Z3Solver();
			symx::TransVisitor* create_translator();
			symx::TransVisitor* create_translator(
				const symx::refSolverExpr mem,
				const std::unordered_map
					<unsigned int,symx::refSolverExpr> &reg,
				const std::unordered_map
					<unsigned int,symx::refSolverCond> &flag
			);

		private:
			static void error_handler(
				Z3_context ctx,
				Z3_error_code error
			) {
				err("Z3 Solver: %s\n",
					Z3_get_error_msg_ex(ctx,error));
			}
	};
	class Z3SolverExpr : public symx::SolverExpr {
		public:
			Z3_context context;
			Z3_ast ast;
			Z3SolverExpr(Z3_context _context,Z3_ast _ast);
			~Z3SolverExpr();
	};
	class Z3SolverCond : public symx::SolverCond {
		public:
			Z3_context context;
			Z3_ast ast;
			Z3SolverCond(Z3_context _context,Z3_ast _ast);
			~Z3SolverCond();
	};
};

#endif
