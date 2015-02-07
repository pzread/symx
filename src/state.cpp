#define LOG_PREFIX "state"

#include<memory>
#include<string>
#include<unordered_map>
#include<vector>

#include"utils.h"
#include"context.h"
#include"expr.h"
#include"state.h"
#include"solver.h"

using namespace symx;

namespace symx {

class PrintVisitor : public ExprVisitor {
	public:
		int print(refExpr expr){
			info("%s\n",expr_map[expr].c_str());
			return 0;
		}
		int visit(refBytMem mem) {
			if(mem->type == ExprMem) {
				expr_map[mem] = "(mem " +
					std::to_string(mem->id) +
					")";
			} else if(mem->type == ExprDangle) {
				expr_map[mem] = "(dmem)";
			}
			return 0;
		}
		int visit(refBytVec vec) {
			if(vec->type == ExprImm) {
				expr_map[vec] = "(imm " +
					std::to_string(vec->data) +
					")";
			} else if(vec->type == ExprVar) {
				expr_map[vec] = "(var " +
					std::to_string(vec->id) +
					")";
			} else if(vec->type == ExprDangle) {
				expr_map[vec] = "(dvec " +
					std::to_string(vec->index) +
					")";
			}
			return 0;
		}
		int visit(refOperator oper) {
			unsigned int i;
			std::string params;

			switch(oper->type) {
			case ExprOpSelect:
				params = "select " +
					expr_map[oper->operand[0]] + "," +
					expr_map[oper->operand[1]];
				break;
			case ExprOpExtract:
				params = "extract " +
					expr_map[oper->operand[0]] + "," +
					std::to_string(oper->start);
				break;
			default:
				params = expr_map[oper->operand[0]];
				for(i = 1; i < oper->op_count; i++) {
					params += "," +
						expr_map[oper->operand[i]];
				}
				break;
			}
			expr_map[oper] = "(" + params + ")";
			return 0;
		}
		int visit(refCond cond) {
			return 0;
		}
	private:
		std::unordered_map<refExpr,std::string> expr_map;
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
static refState create_static_state(Context *ctx,refProbe probe,uint64_t pc) {
	unsigned int i;
	auto nstate = ref<State>(pc,probe);
	auto vis = ctx->solver->create_translator();

	nstate->mem = BytMem::create_var(ctx);
	expr_walk(vis,nstate->mem);
	nstate->solver_mem = vis->get_solver_expr(nstate->mem);

	for(i = 0; i < ctx->num_reg; i++) {
		nstate->reg[i] = BytVec::create_imm(
			ctx->reg_size,
			probe->read_reg(i));
		expr_walk(vis,nstate->reg[i]);
		nstate->solver_reg[i] = vis->get_solver_expr(nstate->reg[i]);
		nstate->reg[i]->solver_expr = nstate->solver_reg[i];
	}
	for(i = 0; i < ctx->num_flag; i++) {
		if(probe->read_flag(i)) {
			nstate->flag[i] = Cond::create_true();
		} else {
			nstate->flag[i] = Cond::create_false();
		}
		expr_walk(vis,nstate->flag[i]);
		nstate->solver_flag[i] = vis->get_solver_cond(nstate->flag[i]);
		nstate->flag[i]->solver_cond = nstate->solver_flag[i];
	}

	delete vis;

	return nstate;
}
int state_executor(Context *ctx,refProbe probe,uint64_t pc) {
	unsigned int i;
	Solver *solver = ctx->solver;
	refState nstate,cstate;
	refBlock cblk;
	std::unordered_map<unsigned int,refSolvExpr> solver_reg;
	std::unordered_map<unsigned int,refSolvCond> solver_flag;
	std::vector<refSolvCond> cons;
	std::unordered_map<refSolvExpr,uint64_t> var;

	nstate = create_static_state(ctx,probe,pc);
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

		/*
		auto vis = new PrintVisitor();
		expr_walk(vis,cblk->mem);
		vis->print(cblk->mem);
		delete vis;
		for(i = 0; i < ctx->num_reg; i++) {
			auto vis = new PrintVisitor();
			expr_walk(vis,cblk->reg[i]);
			vis->print(cblk->reg[i]);
			delete vis;
		}
		*/

		solver_reg.clear();
		solver_flag.clear();
		for(i = 0;i < ctx->num_reg;i++) {
			solver_reg[i] = cstate->solver_reg[i];
		}
		for(i = 0;i < ctx->num_flag;i++) {
			solver_flag[i] = cstate->solver_flag[i];
		}

		auto vis = solver->create_translator(
				cstate->solver_mem,solver_reg,solver_flag);
		expr_walk(vis,cblk->mem);
		for(i = 0;i < ctx->num_reg;i++) {
			expr_walk(vis,cblk->reg[i]);
		}
		for(i = 0;i < ctx->num_flag;i++) {
			expr_walk(vis,cblk->flag[i]);
		}

		auto solexpr_pc = vis->get_solver_expr(
				cblk->reg[ctx->REGIDX_PC]);
		cons.clear();
		var.clear();
		var[solexpr_pc] = 0;
		while(true) {
			if(!solver->solve(cons,&var)) {
				break;	
			}

			uint64_t next_pc = var[solexpr_pc];
			info("next pc %lx\n",next_pc);

			auto exclude_cond = cond_not(
				cond_eq(
					cblk->reg[ctx->REGIDX_PC],
					BytVec::create_imm(4,next_pc)));
			expr_walk(vis,exclude_cond);
			cons.push_back(vis->get_solver_cond(exclude_cond));
		}

		delete vis;

		break;
	}
	return 0;
}

};
