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
		const refSolverExpr mem,
		const std::unordered_map <unsigned int,refSolverExpr> &reg,
		const std::unordered_map <unsigned int,refSolverCond> &flag
	) :
		solver(_solver),
		dangle_mem(mem),
		dangle_reg(reg),
		dangle_flag(flag) 
	{
		bvsort1 = Z3_mk_bv_sort(solver->context,8);
		bvsort4 = Z3_mk_bv_sort(solver->context,32);
	}
	Z3TransVisitor::~Z3TransVisitor() {
		for(auto it = expr_ast.begin();
				it != expr_ast.end();
				it++){
			DECREF(it->second);
		}
		for(auto it = cond_ast.begin();
				it != cond_ast.end();
				it++){
			DECREF(it->second);
		}
	}
	symx::refSolverExpr Z3TransVisitor::get_solver_expr(
			const symx::refExpr expr) {
		return ref<Z3SolverExpr>(solver->context,expr_ast[expr]);
	}
	symx::refSolverCond Z3TransVisitor::get_solver_cond(
			const symx::refCond cond) {
		return ref<Z3SolverCond>(solver->context,cond_ast[cond]);
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
			break;
		}
		case ExprImm:
			res_ast = Z3_mk_unsigned_int64(
				solver->context,
				vec->data,
				bvsort4);
			break;
		case ExprVar:
			res_ast = Z3_mk_const(
					solver->context,
					Z3_mk_int_symbol(
						solver->context,
						vec->id),
					bvsort4);
			break;
		default:
			err("illegal case\n");
			return -1;
		}
		INCREF(res_ast);
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
			break;
		default:
			err("illegal case\n");
			return -1;
		}
		INCREF(res_ast);
		expr_ast[mem] = res_ast;
		return 0;
	}
	int Z3TransVisitor::visit(const refOperator oper) {
		return 0;
	}
	int Z3TransVisitor::visit(const refCond cond) {
		Z3_ast res_ast;
		switch(cond->type) {
		case CondDangle:
		{
			auto cond_it = dangle_flag.find(cond->index);
			if(cond_it == dangle_flag.end()) {
				err("undefined dangle bytvec\n");
			}
			auto cond = std::static_pointer_cast<Z3SolverCond>(
					cond_it->second);
			res_ast = cond->ast;
			break;
		}
		case CondFalse:
			res_ast = Z3_mk_false(solver->context);
			break;
		case CondTrue:
			res_ast = Z3_mk_true(solver->context);
			break;
		default:
			err("illegal case\n");
			return -1;
		}
		INCREF(res_ast);
		cond_ast[cond] = res_ast;
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
			const symx::refSolverExpr mem,
			const std::unordered_map
				<unsigned int,symx::refSolverExpr> &reg,
			const std::unordered_map
				<unsigned int,symx::refSolverCond> &flag
	) {
		return new Z3TransVisitor(this,mem,reg,flag);
	}
};