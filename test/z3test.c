#include<stdio.h>
#include<stdlib.h>
#include<z3.h>

static void error_handler(Z3_context ctx,Z3_error_code error) {
	fprintf(stderr,"Z3 Solver: %s\n",Z3_get_error_msg_ex(ctx,error));
}
int main(){
	Z3_context context;
	Z3_solver solver;
	Z3_sort bvsort1;
	Z3_sort bvsort4;
	Z3_ast x_ast,y_ast,z_ast,u_ast,v_ast,w_ast,test_ast;
	Z3_model model;

	Z3_config config = Z3_mk_config();
	Z3_set_param_value(config,"model","true");
	context = Z3_mk_context_rc(config);
	Z3_set_error_handler(context,error_handler);

	solver = Z3_mk_solver(context);
	Z3_solver_inc_ref(context,solver);

	bvsort1 = Z3_mk_bv_sort(context,8);
	bvsort4 = Z3_mk_bv_sort(context,32);

	x_ast = Z3_mk_const(context,Z3_mk_int_symbol(context,1),bvsort4);
	Z3_inc_ref(context,x_ast);
	y_ast = Z3_mk_unsigned_int64(context,67,bvsort4);
	Z3_inc_ref(context,y_ast);
	z_ast = Z3_mk_unsigned_int64(context,289,bvsort4);
	Z3_inc_ref(context,z_ast);

	u_ast = Z3_mk_const(context,Z3_mk_int_symbol(context,2),bvsort4);
	Z3_inc_ref(context,u_ast);
	v_ast = Z3_mk_unsigned_int64(context,2501,bvsort4);
	Z3_inc_ref(context,v_ast);
	w_ast = Z3_mk_eq(context,u_ast,v_ast);
	Z3_inc_ref(context,w_ast);

	Z3_dec_ref(context,u_ast);
	Z3_dec_ref(context,v_ast);

	u_ast = Z3_mk_ite(context,w_ast,y_ast,z_ast);
	Z3_inc_ref(context,u_ast);

	test_ast = Z3_mk_eq(context,x_ast,u_ast);
	Z3_inc_ref(context,test_ast);
	Z3_solver_assert(context,solver,test_ast);

	Z3_solver_check(context,solver);
	model = Z3_solver_get_model(context,solver);
	fprintf(stderr,"%s\n",Z3_model_to_string(context,model));

	return 0;
}
