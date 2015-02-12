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
	Z3SolvExpr::Z3SolvExpr(Z3_context _context,Z3_ast _ast)
		: context(_context),ast(_ast) {
		Z3_inc_ref(context,ast);
	}
	Z3SolvExpr::~Z3SolvExpr() {
		Z3_dec_ref(context,ast);
	}
	Z3SolvCond::Z3SolvCond(Z3_context _context,Z3_ast _ast)
		: context(_context),ast(_ast) {
		Z3_inc_ref(context,ast);
	}
	Z3SolvCond::~Z3SolvCond() {
		Z3_dec_ref(context,ast);
	}
	Z3TransVisitor::Z3TransVisitor(const Z3Solver *_solver)
		: solver(_solver) {
		bvsort1 = Z3_mk_bv_sort(solver->context,8);
		bvsort4 = Z3_mk_bv_sort(solver->context,32);
		bvimm41 = Z3_mk_unsigned_int64(solver->context,1,bvsort4);
		INCREF(bvimm41);
	}
	Z3_ast Z3TransVisitor::expr_to_ast(const symx::refExpr expr) {
		if(expr->solver_expr == nullptr) {
			err("expr hasn't been translated\n");
		}
		return std::static_pointer_cast<Z3SolvExpr>
			(expr->solver_expr)->ast;
	}
	Z3_ast Z3TransVisitor::cond_to_ast(const symx::refCond cond) {
		if(cond->solver_cond == nullptr) {
			err("cond hasn't been translated\n");
		}
		return std::static_pointer_cast<Z3SolvCond>
			(cond->solver_cond)->ast;
	}
	int Z3TransVisitor::pre_visit(symx::refBytVec vec) {
		if(vec->solver_expr != nullptr) {
			return 0;
		}
		return 1;
	}
	int Z3TransVisitor::pre_visit(symx::refBytMem mem) {
		if(mem->solver_expr != nullptr) {
			return 0;
		}
		return 1;
	}
	int Z3TransVisitor::pre_visit(symx::refOperator oper) {
		if(oper->solver_expr != nullptr) {
			return 0;
		}
		return 1;
	}
	int Z3TransVisitor::pre_visit(symx::refCond cond) {
		if(cond->solver_cond != nullptr) {
			return 0;
		}
		return 1;
	}
	int Z3TransVisitor::post_visit(const refBytVec vec) {
		Z3_ast res_ast;
		switch(vec->type) {
		case ExprImm:
			res_ast = Z3_mk_unsigned_int64(
				solver->context,
				vec->data,
				Z3_mk_bv_sort(solver->context,vec->size * 8));
			INCREF(res_ast);
			break;
		case ExprVar:
			res_ast = Z3_mk_const(
				solver->context,
				Z3_mk_int_symbol(
					solver->context,
					vec->id),
				Z3_mk_bv_sort(solver->context,vec->size * 8));
			INCREF(res_ast);
			break;
		default:
			err("illegal case\n");
			return -1;
		}
		vec->solver_expr = ref<Z3SolvExpr>(solver->context,res_ast);
		DECREF(res_ast);
		return 0;
	}
	int Z3TransVisitor::post_visit(const refBytMem mem) {
		Z3_ast res_ast;
		switch(mem->type) {
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
		mem->solver_expr = ref<Z3SolvExpr>(solver->context,res_ast);
		DECREF(res_ast);
		return 0;
	}
	int Z3TransVisitor::post_visit(const refOperator oper) {
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
						tmp_ast,
						res_ast);
				INCREF(res_ast);
				DECREF(tmp_ast);
				DECREF(old_res_ast);
			}
			DECREF(idx_ast);
			break;
		}
		case ExprOpExtract:
			res_ast = Z3_mk_extract(
				solver->context,
				(oper->start + oper->size) * 8 - 1,
				oper->start * 8,
				expr_to_ast(oper->operand[0]));
			INCREF(res_ast);
			break;
		case ExprOpIte:
			res_ast = Z3_mk_ite(
				solver->context,
				cond_to_ast(oper->cond),
				expr_to_ast(oper->operand[0]),
				expr_to_ast(oper->operand[1]));
			INCREF(res_ast);
			break;
		case ExprOpAdd:
			res_ast = Z3_mk_bvadd(
				solver->context,
				expr_to_ast(oper->operand[0]),
				expr_to_ast(oper->operand[1]));
			INCREF(res_ast);
			break;
		case ExprOpSub:
			res_ast = Z3_mk_bvsub(
				solver->context,
				expr_to_ast(oper->operand[0]),
				expr_to_ast(oper->operand[1]));
			INCREF(res_ast);
			break;
		case ExprOpMul:
			res_ast = Z3_mk_bvmul(
				solver->context,
				expr_to_ast(oper->operand[0]),
				expr_to_ast(oper->operand[1]));
			INCREF(res_ast);
			break;
		case ExprOpUdiv:
			res_ast = Z3_mk_bvudiv(
				solver->context,
				expr_to_ast(oper->operand[0]),
				expr_to_ast(oper->operand[1]));
			INCREF(res_ast);
			break;
		case ExprOpSdiv:
			res_ast = Z3_mk_bvsdiv(
				solver->context,
				expr_to_ast(oper->operand[0]),
				expr_to_ast(oper->operand[1]));
			INCREF(res_ast);
			break;
		case ExprOpAnd:
			res_ast = Z3_mk_bvand(
				solver->context,
				expr_to_ast(oper->operand[0]),
				expr_to_ast(oper->operand[1]));
			INCREF(res_ast);
			break;
		case ExprOpOr:
			res_ast = Z3_mk_bvor(
				solver->context,
				expr_to_ast(oper->operand[0]),
				expr_to_ast(oper->operand[1]));
			INCREF(res_ast);
			break;
		case ExprOpXor:
			res_ast = Z3_mk_bvxor(
				solver->context,
				expr_to_ast(oper->operand[0]),
				expr_to_ast(oper->operand[1]));
			INCREF(res_ast);
			break;
		case ExprOpNeg:
			res_ast = Z3_mk_bvneg(
				solver->context,
				expr_to_ast(oper->operand[0]));
			INCREF(res_ast);
			break;
		case ExprOpNot:
			res_ast = Z3_mk_bvnot(
				solver->context,
				expr_to_ast(oper->operand[0]));
			INCREF(res_ast);
			break;
		case ExprOpConcat:
			res_ast = Z3_mk_concat(
				solver->context,
				expr_to_ast(oper->operand[1]),
				expr_to_ast(oper->operand[0]));
			INCREF(res_ast);
			break;
		case ExprOpSext:
			res_ast = Z3_mk_sign_ext(
				solver->context,
				(oper->size - oper->operand[0]->size) * 8,
				expr_to_ast(oper->operand[0]));
			INCREF(res_ast);
			break;
		case ExprOpZext:
			res_ast = Z3_mk_zero_ext(
				solver->context,
				(oper->size - oper->operand[0]->size) * 8,
				expr_to_ast(oper->operand[0]));
			INCREF(res_ast);
			break;
		default:
			err("illegal case\n");
			return -1;
		}
		oper->solver_expr = ref<Z3SolvExpr>(solver->context,res_ast);
		DECREF(res_ast);
		return 0;
	}
	int Z3TransVisitor::post_visit(const refCond cond) {
		Z3_ast res_ast;
		switch(cond->type) {
		case CondFalse:
			res_ast = Z3_mk_false(solver->context);
			INCREF(res_ast);
			break;
		case CondTrue:
			res_ast = Z3_mk_true(solver->context);
			INCREF(res_ast);
			break;
		case CondEq:
			res_ast = Z3_mk_eq(
					solver->context,
					expr_to_ast(cond->expr[0]),
					expr_to_ast(cond->expr[1]));
			INCREF(res_ast);
			break;
		case CondSl:
			res_ast = Z3_mk_bvslt(
					solver->context,
					expr_to_ast(cond->expr[0]),
					expr_to_ast(cond->expr[1]));
			INCREF(res_ast);
			break;
		case CondSle:
			res_ast = Z3_mk_bvsle(
					solver->context,
					expr_to_ast(cond->expr[0]),
					expr_to_ast(cond->expr[1]));
			INCREF(res_ast);
			break;
		case CondUl:
			res_ast = Z3_mk_bvult(
					solver->context,
					expr_to_ast(cond->expr[0]),
					expr_to_ast(cond->expr[1]));
			INCREF(res_ast);
			break;
		case CondUle:
			res_ast = Z3_mk_bvule(
					solver->context,
					expr_to_ast(cond->expr[0]),
					expr_to_ast(cond->expr[1]));
			INCREF(res_ast);
			break;
		case CondSg:
			res_ast = Z3_mk_bvsgt(
					solver->context,
					expr_to_ast(cond->expr[0]),
					expr_to_ast(cond->expr[1]));
			INCREF(res_ast);
			break;
		case CondSge:
			res_ast = Z3_mk_bvsge(
					solver->context,
					expr_to_ast(cond->expr[0]),
					expr_to_ast(cond->expr[1]));
			INCREF(res_ast);
			break;
		case CondUg:
			res_ast = Z3_mk_bvugt(
					solver->context,
					expr_to_ast(cond->expr[0]),
					expr_to_ast(cond->expr[1]));
			INCREF(res_ast);
			break;
		case CondUge:
			res_ast = Z3_mk_bvuge(
					solver->context,
					expr_to_ast(cond->expr[0]),
					expr_to_ast(cond->expr[1]));
			INCREF(res_ast);
			break;
		case CondIte:
		{
			res_ast = Z3_mk_ite(
				solver->context,
				cond_to_ast(cond->cond[0]),
				cond_to_ast(cond->cond[1]),
				cond_to_ast(cond->cond[2]));
			INCREF(res_ast);
			break;
		}
		case CondAnd:
		{
			Z3_ast conds[] = {
				cond_to_ast(cond->cond[0]),
				cond_to_ast(cond->cond[1])};
			res_ast = Z3_mk_and(solver->context,2,conds);
			INCREF(res_ast);
			break;
		}
		case CondOr:
		{
			Z3_ast conds[] = {
				cond_to_ast(cond->cond[0]),
				cond_to_ast(cond->cond[1])};
			res_ast = Z3_mk_or(solver->context,2,conds);
			INCREF(res_ast);
			break;
		}
		case CondXor:
			res_ast = Z3_mk_xor(
					solver->context,
					cond_to_ast(cond->cond[0]),
					cond_to_ast(cond->cond[1]));
			INCREF(res_ast);
			break;
		case CondNot:
			res_ast = Z3_mk_not(
					solver->context,
					cond_to_ast(cond->cond[0]));
			INCREF(res_ast);
			break;
		default:
			err("illegal case\n");
			return -1;
		}
		cond->solver_cond = ref<Z3SolvCond>(solver->context,res_ast);
		DECREF(res_ast);
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
		return new Z3TransVisitor(this);
	}
	bool Z3Solver::solve(
		const std::unordered_set<refSolvCond> &cons,
		std::unordered_map<refSolvExpr,uint64_t> *var
	) {
		refZ3SolvExpr expr;
		Z3_model model;
		Z3_ast res_ast;

		Z3_solver_reset(context,solver);
		for(auto it = cons.begin(); it != cons.end(); it++) {
			auto cond = std::static_pointer_cast<Z3SolvCond>(*it);
			Z3_solver_assert(context,solver,cond->ast);
		}
		if(Z3_solver_check(context,solver) != Z3_TRUE) {
			return false;
		}

		model = Z3_solver_get_model(context,solver);
		Z3_model_inc_ref(context,model);
		
		for(auto it = var->begin(); it != var->end(); it++) {
			expr = std::static_pointer_cast
				<Z3SolvExpr>(it->first);
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
		return true;
	}
};
