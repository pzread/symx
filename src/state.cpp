#define LOG_PREFIX "state"

#include<memory>
#include<vector>
#include<string>
#include<unordered_map>

#include"utils.h"
#include"context.h"
#include"expr.h"
#include"state.h"
#include"solver.h"

using namespace symx;

namespace symx {

class PrintVisitor : public ExprVisitor {
	public:
		int print(){
			info("%s\n",str_stack.front().c_str());
			return 0;
		}
		int visit(refBytMem mem) {
			if(mem->type == ExprMem) {
				str_stack.push_back(
					"(mem " +
					std::to_string(mem->id) +
					")");
			} else if(mem->type == ExprDangle) {
				str_stack.push_back(
					"(dmem " +
					std::to_string(mem->id) +
					")");
			}
			return 0;
		}
		int visit(refBytVec vec) {
			if(vec->type == ExprImm) {
				str_stack.push_back(
					"(imm " +
					std::to_string(vec->data) +
					")");
			} else if(vec->type == ExprVar) {
				str_stack.push_back(
					"(var " +
					std::to_string(vec->id) +
					")");
			} else if(vec->type == ExprDangle) {
				str_stack.push_back(
					"(dvec " +
					std::to_string(vec->id) +
					")");
			}
			return 0;
		}
		int visit(refOperator oper) {
			unsigned int i;
			std::string params;

			switch(oper->type) {
			case ExprOpSelect:
				params = "select " +
					str_stack[1] + "," + str_stack[0];
				str_stack.pop_back();
				str_stack.pop_back();
				break;
			case ExprOpExtract:
				params = "extract " + str_stack[0] + "," +
					std::to_string(oper->start);
				str_stack.pop_back();
				break;
			default:
				params = str_stack.back();
				str_stack.pop_back();
				for(i = 1; i < oper->op_count; i++) {
					params = str_stack.back() +
						"," + params;
					str_stack.pop_back();
				}
				break;
			}
			str_stack.push_back("(" + params + ")");
			return 0;
		}
		int visit(refCond cond) {
			return 0;
		}
	private:
		std::vector<std::string> str_stack;
		std::unordered_map<refExpr,int> expr_map;
};

refBlock state_create_block(Context *ctx) {
	unsigned int i;
	refBlock blk =  ref<Block>();

	blk->mem = BytMem::create_dangle(-1);
	for(i = 0; i < ctx->num_reg; i++) {
		blk->reg[i] = BytVec::create_dangle(ctx->reg_size,i);
	}
	for(i = 0;i < ctx->num_flag; i++) {
		blk->flag[i] = Cond::create_dangle(i);
	}
	return blk;
}
int state_executor(Context *ctx,refProbe probe,uint64_t pc) {
	unsigned int i;
	refState nstate,cstate;
	refBlock cblk;
	TransVisitor *vis;
	
	vis = ctx->solver->create_translator();
	nstate = ref<State>(pc,probe);

	nstate->mem = BytMem::create_var(ctx);
	expr_walk(vis,nstate->mem);
	nstate->solver_mem = vis->get_solver_expr(nstate->mem);

	for(i = 0; i < ctx->num_reg; i++) {
		nstate->reg[i] = BytVec::create_imm(
			ctx->reg_size,
			probe->read_reg(i));
		expr_walk(vis,nstate->reg[i]);
		nstate->solver_reg[i] = vis->get_solver_expr(nstate->reg[i]);
	}
	for(i = 0; i < ctx->num_flag; i++) {
		if(probe->read_flag(i)) {
			nstate->flag[i] = Cond::create_true();
		} else {
			nstate->flag[i] = Cond::create_false();
		}
		expr_walk(vis,nstate->flag[i]);
		nstate->solver_flag[i] = vis->get_solver_cond(nstate->flag[i]);
	}
	ctx->state.push(nstate);

	while(!ctx->state.empty()) {
		cstate = ctx->state.front();
		ctx->state.pop();

		auto blk_it = ctx->block.find(pc);
		if(blk_it == ctx->block.end()) {
			cblk = ctx->interpret(probe,pc);
		} else {
			cblk = blk_it->second;
		}

		auto vis = new PrintVisitor();
		expr_walk(vis,cblk->mem);
		vis->print();
		delete vis;
		for(i = 0; i < ctx->num_reg; i++) {
			auto vis = new PrintVisitor();
			expr_walk(vis,cblk->reg[i]);
			vis->print();
			delete vis;
		}

		break;
	}
	return 0;
}

};
