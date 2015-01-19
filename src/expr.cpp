#include<stdint.h>

#include"expr.h"

static uint64_t get_next_varid(Context *ctx){
	ctx->last_var_id += 1;
	return ctx->last_var_id;
}
BytVec::BytVec(Context *ctx,const unsigned int size):
	Expr(ExprVar,size),
	data(get_next_varid(ctx)) {}
