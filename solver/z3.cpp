#define LOG_PREFIX "z3_solver"

#include<z3.h>
#include<unordered_map>
#include"utils.h"
#include"expr.h"
#include"z3.h"

using namespace symx;

#define INCREF(x) Z3_inc_ref(solver->context,(x))
#define DECREF(x) Z3_dec_ref(solver->context,(x))

namespace z3_solver {
	Z3SolverExpr::Z3SolverExpr(Z3_context _context,Z3_ast _ast)
		: context(_context),ast(_ast) {
		Z3_inc_ref(context,ast);
	}
	Z3SolverExpr::~Z3SolverExpr() {
		Z3_dec_ref(context,ast);
	}
	Z3SolverCond::Z3SolverCond(Z3_context _context,Z3_ast _ast)
		: context(_context),ast(_ast) {
		Z3_inc_ref(context,ast);
	}
	Z3SolverCond::~Z3SolverCond() {
		Z3_dec_ref(context,ast);
	}
	Z3TransVisitor::Z3TransVisitor(
		const Z3Solver *_solver,
		const refSolverExpr _mem,
		const std::unordered_map <unsigned int,refSolverExpr> &_reg,
		const std::unordered_map <unsigned int,refSolverCond> &_cond
	) :
		solver(_solver),
		dangle_mem(_mem),
		dangle_reg(_reg),
		dangle_cond(_cond) 
	{
		bvsort1 = Z3_mk_bv_sort(solver->context,8);
		bvsort4 = Z3_mk_bv_sort(solver->context,32);
	}
	symx::refSolverExpr Z3TransVisitor::get_solverexpr(
			const symx::refExpr expr) {
		auto z3expr = ref<Z3SolverExpr>(solver->context,expr_ast[expr]);
		return z3expr;
	}
	symx::refSolverCond Z3TransVisitor::get_solvercond(
			const symx::refCond cond) {
		auto z3cond = ref<Z3SolverCond>(solver->context,cond_ast[cond]);
		return z3cond;
	}
	int Z3TransVisitor::visit(const refBytVec vec) {
		Z3_ast res_ast;
		switch(vec->type) {
		case ExprDangle:
		{
			auto expr_it = dangle_reg.find(vec->index);
			if(expr_it == dangle_reg.end()) {
				err("undefined dangle bytvec\n");
			}
			auto expr = std::static_pointer_cast<Z3SolverExpr>(
					expr_it->second);
			res_ast = expr->ast;
			INCREF(res_ast);
			break;
		}
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
			return -1;
		}
		expr_ast[vec] = res_ast;
		return 0;
	}
	int Z3TransVisitor::visit(const refBytMem mem) {
		Z3_ast res_ast;
		switch(mem->type) {
		case ExprDangle:
		if(dangle_mem == nullptr) {
			err("undefined dangle bytmem\n");
		} else {
			auto expr = std::static_pointer_cast<Z3SolverExpr>(
					dangle_mem);
			res_ast = expr->ast;
			INCREF(res_ast);
			break;
		}
		case ExprMem:
			res_ast = Z3_mk_const(
					solver->context,
					Z3_mk_int_symbol(
						solver->context,
						mem->id),
					Z3_mk_array_sort(
						solver->context,
						bvsort4,
						bvsort1));
			INCREF(res_ast);
			break;
		default:
			err("illegal case\n");
			return -1;
		}
		expr_ast[mem] = res_ast;
		return 0;
	}
	int Z3TransVisitor::visit(const refOperator oper) {
		return 0;
	}
	int Z3TransVisitor::visit(const refCond cond) {
		return 0;
	}
	Z3Solver::Z3Solver() {
		Z3_config config = Z3_mk_config();
    		Z3_set_param_value(config,"model","true");
		context = Z3_mk_context_rc(config);
    		Z3_set_error_handler(context,error_handler);
		
		solver = Z3_mk_solver(context);
		Z3_solver_inc_ref(context,solver);
	}
	symx::TransVisitor* Z3Solver::create_translator() {
		return new Z3TransVisitor(
				this,
				nullptr,
				std::unordered_map
				<unsigned int,
				symx::refSolverExpr>{},
				std::unordered_map
				<unsigned int,
				symx::refSolverCond>{});
	}
	symx::TransVisitor* Z3Solver::create_translator(
			const symx::refSolverExpr _mem,
			const std::unordered_map
			<unsigned int,
			symx::refSolverExpr> &_reg,
			const std::unordered_map
			<unsigned int,
			symx::refSolverCond> &_cond
	) {
		return new Z3TransVisitor(this,_mem,_reg,_cond);
	}
};
