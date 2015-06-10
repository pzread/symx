#define LOG_PREFIX "z3_solver"

#include<assert.h>
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
Z3TransVisitor::Z3TransVisitor(const Z3Solver *_solver) : solver(_solver) {
	bvsort1 = Z3_mk_bv_sort(solver->context,8);
	bvsort4 = Z3_mk_bv_sort(solver->context,32);
	bvimm41 = Z3_mk_unsigned_int64(solver->context,1,bvsort4);
	INCREF(bvimm41);

	simplify_param = Z3_mk_params(solver->context);
	Z3_params_inc_ref(solver->context,simplify_param);
	Z3_params_set_bool(
		solver->context,
		simplify_param,
		Z3_mk_string_symbol(solver->context,"sort_store"),
		Z3_TRUE);
	Z3_params_set_bool(
		solver->context,
		simplify_param,
		Z3_mk_string_symbol(solver->context,"mul2concat"),
		Z3_TRUE);
}
Z3_ast Z3TransVisitor::expr_to_ast(const refExpr &expr) {
        auto it = cache_expr.find(expr);
	if(it == cache_expr.end()) {
		err("expr hasn't been translated\n");
	}
	return it->second->ast;
}
Z3_ast Z3TransVisitor::cond_to_ast(const refCond &cond) {
        auto it = cache_cond.find(cond);
        if(it == cache_cond.end()) {
		err("cond hasn't been translated\n");
	}
        return it->second->ast;
}
int Z3TransVisitor::pre_visit(const refBytVec &vec) {
	if(cache_expr.find(vec) != cache_expr.end()) {
		return 0;
	}
	return 1;
}
int Z3TransVisitor::pre_visit(const refBytMem &mem) {
	if(cache_expr.find(mem) != cache_expr.end()) {
		return 0;
	}
	return 1;
}
int Z3TransVisitor::pre_visit(const refOperator &oper) {
	if(cache_expr.find(oper) != cache_expr.end()) {
		return 0;
	}
	return 1;
}
int Z3TransVisitor::pre_visit(const refCond &cond) {
	if(cache_cond.find(cond) != cache_cond.end()) {
		return 0;
	}
	return 1;
}
int Z3TransVisitor::post_visit(const refBytVec &vec) {
	Z3_ast res_ast;
	switch(vec->type) {
	case ExprImm:
		res_ast = Z3_mk_unsigned_int64(
			solver->context,
			vec->data,
			Z3_mk_bv_sort(solver->context,vec->size));
		INCREF(res_ast);
		break;
	case ExprVar:
		res_ast = Z3_mk_const(
			solver->context,
			Z3_mk_int_symbol(
				solver->context,
				vec->id),
			Z3_mk_bv_sort(solver->context,vec->size));
		INCREF(res_ast);
		break;
	default:
		err("illegal case\n");
		return -1;
	}
        cache_expr[vec] = ref<Z3SolvExpr>(solver->context,res_ast);
	DECREF(res_ast);
	return 0;
}
int Z3TransVisitor::post_visit(const refBytMem &mem) {
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
        cache_expr[mem] = ref<Z3SolvExpr>(solver->context,res_ast);
	DECREF(res_ast);
	return 0;
}
int Z3TransVisitor::post_visit(const refOperator &oper) {
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

		assert(size % 8 == 0);

		INCREF(mem_ast);
		INCREF(idx_ast);
		for(i = 0; i < size; i += 8) {
			Z3_ast tmp_ast = Z3_mk_extract(
					solver->context,
					i + 7,
					i,
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

		assert(size % 8 == 0);

		res_ast = Z3_mk_select(solver->context,mem_ast,idx_ast);
		INCREF(res_ast);
		INCREF(idx_ast);
		for(i = 8; i < size; i += 8) {
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
			(oper->start + oper->size) - 1,
			oper->start,
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
	case ExprOpShl:
		res_ast = Z3_mk_bvshl(
			solver->context,
			expr_to_ast(oper->operand[0]),
			expr_to_ast(oper->operand[1]));
		INCREF(res_ast);
		break;
	case ExprOpLshr:
		res_ast = Z3_mk_bvlshr(
			solver->context,
			expr_to_ast(oper->operand[0]),
			expr_to_ast(oper->operand[1]));
		INCREF(res_ast);
		break;
	case ExprOpAshr:
		res_ast = Z3_mk_bvashr(
			solver->context,
			expr_to_ast(oper->operand[0]),
			expr_to_ast(oper->operand[1]));
		INCREF(res_ast);
		break;
	case ExprOpRor:
		res_ast = Z3_mk_ext_rotate_right(
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
			(oper->size - oper->operand[0]->size),
			expr_to_ast(oper->operand[0]));
		INCREF(res_ast);
		break;
	case ExprOpZext:
		res_ast = Z3_mk_zero_ext(
			solver->context,
			(oper->size - oper->operand[0]->size),
			expr_to_ast(oper->operand[0]));
		INCREF(res_ast);
		break;
	default:
		err("illegal case\n");
		return -1;
	}
	auto old_ast = res_ast;
	res_ast = Z3_simplify_ex(
		solver->context,
		res_ast,
		simplify_param);
	INCREF(res_ast);
	DECREF(old_ast);

	cache_expr[oper] = ref<Z3SolvExpr>(solver->context,res_ast);
	DECREF(res_ast);
	return 0;
}
int Z3TransVisitor::post_visit(const refCond &cond) {
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
	auto old_ast = res_ast;
	res_ast = Z3_simplify_ex(
		solver->context,
		res_ast,
		simplify_param);
	INCREF(res_ast);
	DECREF(old_ast);

        cache_cond[cond] = ref<Z3SolvCond>(solver->context,res_ast);
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

        trans_vis = new Z3TransVisitor(this);
}
Z3Solver::~Z3Solver() {
        delete trans_vis;
}
bool Z3Solver::solve(
	const std::unordered_set<refCond> &cons,
	std::unordered_map<refExpr,uint64_t> *var
) {
	Z3_model model;
	Z3_ast res_ast;

	for(auto it = var->begin(); it != var->end(); it++) {
	    trans_vis->walk(it->first);
	}
	trans_vis->iter_walk(cons.begin(),cons.end());

	Z3_solver_reset(context,solver);

	for(auto it = cons.begin(); it != cons.end(); it++) {
		Z3_solver_assert(context,solver,trans_vis->cond_to_ast(*it));
	}
	if(Z3_solver_check(context,solver) != Z3_TRUE) {
		return false;
	}

	model = Z3_solver_get_model(context,solver);
	Z3_model_inc_ref(context,model);
	for(auto it = var->begin(); it != var->end(); it++) {
		if(Z3_model_eval(
			context,
			model,
			trans_vis->expr_to_ast(it->first),
			Z3_TRUE,
			&res_ast
		) == Z3_FALSE) {
			err("evaluate error\n");
			return false;
		}
		Z3_inc_ref(context,res_ast);
		auto ret = Z3_get_numeral_uint64(
			context,
			res_ast,
			(unsigned __int64*)&it->second);
		Z3_dec_ref(context,res_ast);
		if(ret == Z3_FALSE) {
			err("get numeral error\n");
			return false;
		}
	}
	Z3_model_dec_ref(context,model);

	return true;
}
}
