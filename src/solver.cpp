#define LOG_PREFIX "solver"

#include<z3.h>
#include"utils.h"
#include"expr.h"
#include"solver.h"

using namespace symx;

#define INCREF(x) Z3_inc_ref(solver->context,(x))
#define DECREF(x) Z3_dec_ref(solver->context,(x))

namespace z3_solver {
	TransVisitor::TransVisitor(const Solver *_solver) : solver(_solver) {
		bvsort4 = Z3_mk_bv_sort(solver->context,32);
	}
	int TransVisitor::visit(const refBytVec vec) {
		Z3_ast res_ast;

		switch(vec->type) {
		case ExprDangle:
			break;
		case ExprImm:
			res_ast = Z3_mk_unsigned_int64(
				solver->context,
				vec->data,
				bvsort4);
			INCREF(res_ast);
			break;
		case ExprVar:
			res_ast = Z3_mk_const(
					solver->context,
					Z3_mk_int_symbol(
						solver->context,
						vec->id),
					bvsort4);
			INCREF(res_ast);
			break;
		default:
			err("illegal case\n");
		}
		return 0;
	}
	int TransVisitor::visit(const refBytMem mem) {
		return 0;
	}
	int TransVisitor::visit(const refOperator oper) {
		return 0;
	}
	int TransVisitor::visit(const refCond cond) {
		return 0;
	}
	Solver::Solver() {
		Z3_config config = Z3_mk_config();
    		Z3_set_param_value(config,"model","true");
		context = Z3_mk_context_rc(config);
    		Z3_set_error_handler(context,error_handler);
		
		solver = Z3_mk_solver(context);
		Z3_solver_inc_ref(context,solver);
	}
};
