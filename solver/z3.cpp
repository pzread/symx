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
		bvimm41 = Z3_mk_unsigned_int64(solver->context,1,bvsort4);
		INCREF(bvimm41);
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
	Z3_ast Z3TransVisitor::expr_to_ast(const symx::refExpr expr) {
		auto it = expr_ast.find(expr);
		if(it == expr_ast.end()) {
			err("expr not exist\n");
		}
		return it->second;
	}
	Z3_ast Z3TransVisitor::cond_to_ast(const symx::refCond cond) {
		auto it = cond_ast.find(cond);
		if(it == cond_ast.end()) {
			err("cond not exist\n");
		}
		return it->second;
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
				Z3_mk_bv_sort(solver->context,vec->size * 8));
			break;
		case ExprVar:
			res_ast = Z3_mk_const(
				solver->context,
				Z3_mk_int_symbol(
					solver->context,
					vec->id),
				Z3_mk_bv_sort(solver->context,vec->size * 8));
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
		Z3_ast res_ast;
		switch(oper->type) {
		case ExprOpStore:
		{
			unsigned int i;
			unsigned int size;
			Z3_ast mem_ast = expr_to_ast(oper->operand[0]);
			Z3_ast idx_ast = expr_to_ast(oper->operand[1]);
			Z3_ast val_ast = expr_to_ast(oper->operand[2]);
			Z3_ast old_mem_ast,old_idx_ast;

			size = oper->operand[2]->size;
			INCREF(mem_ast);
			INCREF(idx_ast);
			for(i = 0;i < size;i++) {
				Z3_ast tmp_ast = Z3_mk_extract(
						solver->context,
						i * 8 + 7,
						i * 8,
						val_ast);
				INCREF(tmp_ast);
				old_mem_ast = mem_ast;
				mem_ast = Z3_mk_store(
						solver->context,
						mem_ast,
						idx_ast,
						tmp_ast);
				INCREF(mem_ast);
				DECREF(tmp_ast);
				DECREF(old_mem_ast);
				old_idx_ast = idx_ast;
				idx_ast = Z3_mk_bvadd(
						solver->context,
						idx_ast,
						bvimm41);
				INCREF(idx_ast);
				DECREF(old_idx_ast);
			}
			DECREF(idx_ast);
			res_ast = mem_ast;
			break;
		}
		case ExprOpSelect:
		{
			unsigned int i;
			unsigned int size;
			Z3_ast mem_ast = expr_to_ast(oper->operand[0]);
			Z3_ast idx_ast = expr_to_ast(oper->operand[1]);
			Z3_ast old_idx_ast,old_res_ast;

			if((size = oper->size) == 0){
				err("illegal size\n");
			}
			info("%s\n",Z3_ast_to_string(solver->context,idx_ast));
			res_ast = Z3_mk_select(solver->context,mem_ast,idx_ast);
			INCREF(res_ast);
			INCREF(idx_ast);
			for(i = 1;i < size;i++) {
				old_idx_ast = idx_ast;
				idx_ast = Z3_mk_bvadd(
						solver->context,
						idx_ast,
						bvimm41);
				INCREF(idx_ast);
				DECREF(old_idx_ast);
				Z3_ast tmp_ast = Z3_mk_select(
						solver->context,
						mem_ast,
						idx_ast);
				INCREF(tmp_ast);
				old_res_ast = res_ast;
				res_ast = Z3_mk_concat(
						solver->context,
						res_ast,
						tmp_ast);
				INCREF(res_ast);
				DECREF(tmp_ast);
				DECREF(old_res_ast);
			}
			DECREF(idx_ast);
			break;
		}
		case ExprOpExtract:
			res_ast = Z3_mk_extract(solver->context,
					(oper->start + oper->size) * 8 - 1,
					oper->start * 8,
					expr_to_ast(oper->operand[0]));
			INCREF(res_ast);
			break;
		case ExprOpAdd:
			res_ast = Z3_mk_bvadd(solver->context,
					expr_to_ast(oper->operand[0]),
					expr_to_ast(oper->operand[1]));
			INCREF(res_ast);
			break;
		case ExprOpSub:
			res_ast = Z3_mk_bvsub(solver->context,
					expr_to_ast(oper->operand[0]),
					expr_to_ast(oper->operand[1]));
			INCREF(res_ast);
			break;
		case ExprOpMul:
			res_ast = Z3_mk_bvmul(solver->context,
					expr_to_ast(oper->operand[0]),
					expr_to_ast(oper->operand[1]));
			INCREF(res_ast);
			break;
		case ExprOpUdiv:
			res_ast = Z3_mk_bvudiv(solver->context,
					expr_to_ast(oper->operand[0]),
					expr_to_ast(oper->operand[1]));
			INCREF(res_ast);
			break;
		case ExprOpSdiv:
			res_ast = Z3_mk_bvsdiv(solver->context,
					expr_to_ast(oper->operand[0]),
					expr_to_ast(oper->operand[1]));
			INCREF(res_ast);
			break;
		case ExprOpNeg:
			res_ast = Z3_mk_bvneg(solver->context,
					expr_to_ast(oper->operand[0]));
			INCREF(res_ast);
			break;
		case ExprOpNot:
			res_ast = Z3_mk_bvnot(solver->context,
					expr_to_ast(oper->operand[0]));
			INCREF(res_ast);
			break;
		case ExprOpConcat:
			res_ast = Z3_mk_concat(solver->context,
					expr_to_ast(oper->operand[0]),
					expr_to_ast(oper->operand[1]));
			INCREF(res_ast);
			break;
		default:
			err("illegal case\n");
			return -1;
		}
		expr_ast[oper] = res_ast;
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
		case CondEq:
			res_ast = Z3_mk_eq(
					solver->context,
					expr_to_ast(cond->expr[0]),
					expr_to_ast(cond->expr[1]));
			break;
		case CondSl:
			res_ast = Z3_mk_bvslt(
					solver->context,
					expr_to_ast(cond->expr[0]),
					expr_to_ast(cond->expr[1]));
			break;
		case CondSle:
			res_ast = Z3_mk_bvsle(
					solver->context,
					expr_to_ast(cond->expr[0]),
					expr_to_ast(cond->expr[1]));
			break;
		case CondUl:
			res_ast = Z3_mk_bvult(
					solver->context,
					expr_to_ast(cond->expr[0]),
					expr_to_ast(cond->expr[1]));
			break;
		case CondUle:
			res_ast = Z3_mk_bvule(
					solver->context,
					expr_to_ast(cond->expr[0]),
					expr_to_ast(cond->expr[1]));
			break;
		case CondSg:
			res_ast = Z3_mk_bvsgt(
					solver->context,
					expr_to_ast(cond->expr[0]),
					expr_to_ast(cond->expr[1]));
			break;
		case CondSge:
			res_ast = Z3_mk_bvsge(
					solver->context,
					expr_to_ast(cond->expr[0]),
					expr_to_ast(cond->expr[1]));
			break;
		case CondUg:
			res_ast = Z3_mk_bvugt(
					solver->context,
					expr_to_ast(cond->expr[0]),
					expr_to_ast(cond->expr[1]));
			break;
		case CondUge:
			res_ast = Z3_mk_bvuge(
					solver->context,
					expr_to_ast(cond->expr[0]),
					expr_to_ast(cond->expr[1]));
			break;
		case CondAnd:
		{
			Z3_ast conds[] = {
				cond_to_ast(cond->cond[0]),
				cond_to_ast(cond->cond[1])};
			res_ast = Z3_mk_and(solver->context,2,conds);
			break;
		}
		case CondOr:
		{
			Z3_ast conds[] = {
				cond_to_ast(cond->cond[0]),
				cond_to_ast(cond->cond[1])};
			res_ast = Z3_mk_or(solver->context,2,conds);
			break;
		}
		case CondXor:
			res_ast = Z3_mk_xor(
					solver->context,
					cond_to_ast(cond->cond[0]),
					cond_to_ast(cond->cond[1]));
			break;
		case CondNot:
			res_ast = Z3_mk_not(
					solver->context,
					cond_to_ast(cond->cond[0]));
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
	bool Z3Solver::solve(
			const std::vector<symx::refSolverCond> &cons,
			std::unordered_map<refSolverExpr,uint64_t> *var
	) {
		refZ3SolverExpr expr;
		Z3_model model;
		Z3_ast res_ast;

		Z3_solver_reset(context,solver);
		for(auto it = cons.begin();it != cons.end();it++) {
			auto cond = std::static_pointer_cast<Z3SolverCond>(*it);
			Z3_solver_assert(context,solver,cond->ast);
		}
		if(Z3_solver_check(context,solver) == Z3_FALSE) {
			return false;
		}

		model = Z3_solver_get_model(context,solver);
		Z3_model_inc_ref(context,model);
		
		for(auto it = var->begin();it != var->end();it++) {
			expr = std::static_pointer_cast
				<Z3SolverExpr>(it->first);
			if(Z3_model_eval(
				context,
				model,
				expr->ast,
				Z3_TRUE,
				&res_ast
			) == Z3_FALSE) {
				err("evaluate error\n");
				return false;
			}
			if(Z3_get_numeral_uint64(
				context,
				res_ast,
				(unsigned __int64*)&it->second
			) == Z3_FALSE) {
				err("get numeral error\n");
				return false;
			}
		}

		Z3_model_dec_ref(context,model);
		return false;
	}
};
