#define LOG_PREFIX "state"

#include<memory>
#include<string>
#include<unordered_map>
#include<vector>
#include<bitset>

#include"utils.h"
#include"context.h"
#include"expr.h"
#include"draw.h"
#include"state.h"

using namespace symx;

namespace symx {

AddrSpace::AddrSpace(
	Context *_ctx,
	const refProbe &_probe
) :
	probe(_probe),
	ctx(_ctx)
{
	mem = BytMem::create_var(ctx);
	auto mem_map = probe->get_mem_map();
	for(auto it = mem_map.begin(); it != mem_map.end(); it++) {
		page_map.insert(
			std::make_pair(it->start,MemPage(it->start,it->prot)));
	}
}
refExpr AddrSpace::get_mem() const {
	return mem;
}
int AddrSpace::handle_select(const uint64_t idx,const unsigned int size) {
	int ret = 0;
	uint64_t pos,base;
	unsigned int off;
	uint8_t buf[1];
	refBytVec val;
	std::map<uint64_t,MemPage>::iterator page_it;

	pos = idx;
	while(pos < (idx + size)) {
		base = pos & ~(PAGE_SIZE - 1);
		off = pos & (PAGE_SIZE - 1);

		page_it = page_map.find(base);
		if(page_it == page_map.end()) {
			//err("page out bound\n");
			//for test
			auto page = MemPage(base,PAGE_READ | PAGE_WRITE);
			page_it = page_map.insert(
				std::make_pair(base,page)).first;
		}

		auto &page = page_it->second;
		for(; off < PAGE_SIZE && pos < (idx + size); off++,pos++) {
			if(page.dirty.test(off)) {
				continue;
			}
			
			if(page.prot & PAGE_PROBE) {
				if(probe->read_mem(pos,buf,sizeof(*buf)) != 1) {
					err("read page failed\n");
				}
				val = BytVec::create_imm(1,buf[0]);
			} else {
				//for test
				val = BytVec::create_var(1,ctx);
				mem_symbol.push_back(std::make_pair(pos,val));
			}

			auto byte = expr_select(
				mem,
				BytVec::create_imm(ctx->REGSIZE,pos),
				1);
			mem_constraint.insert(cond_eq(byte,val));

			page.dirty.set(off);
			ret = 1;
		}
	}

	return ret;
}
refExpr BuildVisitor::get_expr(const refExpr expr) {
	auto it = expr_map.find(expr);
	if(it == expr_map.end()) {
		err("expr not exist\n");
		return nullptr;
	}
	return it->second;
}
refCond BuildVisitor::get_cond(const refCond cond) {
	auto it = cond_map.find(cond);
	if(it == cond_map.end()) {
		err("cond not exist\n");
		return nullptr;
	}
	return it->second;
}
int BuildVisitor::get_mem_record(std::unordered_set<refMemRecord> *selrec) {
	selrec->insert(select_record.begin(),select_record.end());
	return 0;
}
int BuildVisitor::pre_visit(const refBytVec &vec) {
	if(expr_map.find(vec) != expr_map.end()) {
		return 0;
	}
	return 1;
}
int BuildVisitor::pre_visit(const refBytMem &mem) {
	if(expr_map.find(mem) != expr_map.end()) {
		return 0;
	}
	return 1;
}
int BuildVisitor::pre_visit(const refOperator &oper) {
	if(expr_map.find(oper) != expr_map.end()) {
		return 0;
	}
	return 1;
}
int BuildVisitor::pre_visit(const refCond &cond) {
	if(cond_map.find(cond) != cond_map.end()) {
		return 0;
	}
	return 1;
}
int BuildVisitor::post_visit(const refBytVec &vec) {
	if(vec->type == ExprDangle) {
		expr_map[vec] = state->reg[vec->index];
	} else {
		expr_map[vec] = ref<BytVec>(vec);
	}
	return 1;
}
int BuildVisitor::post_visit(const refBytMem &mem) {
	if(mem->type == ExprDangle) {
		expr_map[mem] = state->mem;
	} else {
		expr_map[mem] = ref<BytMem>(mem);
	}
	return 1;
}
int BuildVisitor::post_visit(const refOperator &oper) {
	switch(oper->type) {
	case ExprOpSelect:
	{
		auto mem = expr_map[oper->operand[0]];
		auto idx = expr_map[oper->operand[1]];
		expr_map[oper] = expr_select(mem,idx,oper->size);
		select_record.insert(ref<MemRecord>(
			std::static_pointer_cast<Operator>(expr_map[oper]),
			mem,idx,
			oper->size));
		break;
	}
	case ExprOpExtract:
		expr_map[oper] = expr_extract(
			expr_map[oper->operand[0]],
			oper->start,
			oper->start + oper->size);
		break;
	case ExprOpIte:
		expr_map[oper] = expr_ite(
			cond_map[oper->cond],
			expr_map[oper->operand[0]],
			expr_map[oper->operand[1]]);
		break;
	default:
		if(oper->op_count == 1) {
			expr_map[oper] = ref<Operator>(
				oper->type,
				oper->size,
				expr_map[oper->operand[0]]);
		} else if(oper->op_count == 2) {
			expr_map[oper] = ref<Operator>(
				oper->type,
				oper->size,
				expr_map[oper->operand[0]],
				expr_map[oper->operand[1]]);
		} else if(oper->op_count == 3) {
			expr_map[oper] = ref<Operator>(
				expr_map[oper->operand[0]],
				expr_map[oper->operand[1]],
				expr_map[oper->operand[2]]);
		}
		break;
	}
	return 1;
}
int BuildVisitor::post_visit(const refCond &cond) {
	switch(cond->type) {
	case CondDangle:
		cond_map[cond] = state->flag[cond->index];
		break;
	default:
		if(cond->cond_count == 0 && cond->expr_count == 2) {
			cond_map[cond] = ref<Cond>(
				cond->type,
				expr_map[cond->expr[0]],
				expr_map[cond->expr[1]]);
		} else if(cond->cond_count == 1 && cond->expr_count == 0) {
			cond_map[cond] = ref<Cond>(
				cond->type,
				cond_map[cond->cond[0]]);
		} else if(cond->cond_count == 2 && cond->expr_count == 0) {
			cond_map[cond] = ref<Cond>(
				cond->type,
				cond_map[cond->cond[0]],
				cond_map[cond->cond[1]]);
		} else if(cond->cond_count == 3 && cond->expr_count == 0) {
			cond_map[cond] = cond_ite(
				cond_map[cond->cond[0]],
				cond_map[cond->cond[1]],
				cond_map[cond->cond[2]]);
		}
		break;
	}
	return 1;
}

refBlock state_create_block(Context *ctx,const ProgCtr &pc) {
	unsigned int i;
	refBlock blk = ref<Block>(pc);

	blk->mem = BytMem::create_dangle(-1);
	for(i = 0; i < ctx->NUMREG; i++) {
		blk->reg[i] = BytVec::create_dangle(ctx->REGSIZE,i);
	}
	for(i = 0;i < ctx->NUMFLAG; i++) {
		blk->flag[i] = Cond::create_dangle(i);
	}
	return blk;
}
static refState create_static_state(
	Context *ctx,
	const refProbe &probe,
	const AddrSpace &addrsp,
	uint64_t rawpc
) {
	unsigned int i;
	uint64_t value;
	bool symbol;
	int insmd;
	refState nstate;

	insmd = probe->get_insmd();
	nstate = ref<State>(ProgCtr(rawpc,insmd),probe);

	auto vis = ctx->solver->create_translator();

	nstate->mem = addrsp.get_mem();
	expr_walk(vis,nstate->mem);
	for(i = 0; i < ctx->NUMREG; i++) {
		value = probe->read_reg(i,&symbol);
		if(symbol) {
			auto vec = BytVec::create_var(ctx->REGSIZE,ctx);
			nstate->reg[i] = vec;
			nstate->symbol.push_back(vec);
		} else {
			nstate->reg[i] = BytVec::create_imm(
				ctx->REGSIZE,
				value);
		}
		expr_walk(vis,nstate->reg[i]);
	}
	for(i = 0; i < ctx->NUMFLAG; i++) {
		if(probe->read_flag(i)) {
			nstate->flag[i] = Cond::create_true();
		} else {
			nstate->flag[i] = Cond::create_false();
		}
		expr_walk(vis,nstate->flag[i]);
	}

	delete vis;
	return nstate;
}
static refCond create_pc_cond(
	const Context *ctx,
	const refExpr &expc,
	const refExpr &exinsmd,
	const uint64_t rawpc,
	const uint64_t insmd
) {
	return cond_and(
		cond_eq(expc,BytVec::create_imm(ctx->REGSIZE,rawpc)),
		cond_eq(exinsmd,BytVec::create_imm(ctx->REGSIZE,insmd)));
}
static void exclude_pc(
	const Context *ctx,
	std::unordered_set<refCond> *cons,
	const refExpr &expc,
	const refExpr &exinsmd,
	const uint64_t rawpc,
	const int insmd
) {
	cons->insert(cond_not(create_pc_cond(ctx,expc,exinsmd,rawpc,insmd)));
}
int state_executor(
	Context *ctx,
	const refProbe &probe,
	const uint64_t entry_rawpc
) {
	unsigned int i;
	Solver *solver = ctx->solver;
	AddrSpace addrsp(ctx,probe);
	TransVisitor *trans_vis;
	refState nstate,cstate;
	refBlock cblk;
	std::unordered_set<refCond> cons;
	std::unordered_set<refSolvCond> solvcons;
	std::unordered_map<refSolvExpr,uint64_t> var;
	refExpr next_expc;
	refExpr next_exinsmd;
	refExpr next_mem;
	refExpr next_reg[256];
	refCond next_flag[64];
	uint64_t next_rawpc;
	int next_insmd;
	std::unordered_set<refMemRecord> selrec;

	auto draw = Draw();
	bool exp_flag = false;

	nstate = create_static_state(ctx,probe,addrsp,entry_rawpc);
	ctx->state.push(nstate);

	trans_vis = solver->create_translator();
	while(!ctx->state.empty() && !exp_flag) {
		cstate = ctx->state.front();
		ctx->state.pop();
		info("\e[1;32mrun state 0x%x\e[m\n",cstate->pc);

		auto blk_it = ctx->block.find(cstate->pc);
		if(blk_it == ctx->block.end()) {
			cblk = ctx->interpret(probe,cstate->pc);
			ctx->block[cstate->pc] = cblk;

			std::string output;
			for(i = 0;i < cblk->discode.size();i++) {
				output += cblk->discode[i] + "\\l";
			}
			draw.update_block(cblk->pc.rawpc,(char*)output.c_str());
		} else {
			cblk = blk_it->second;
		}

		//initialize
		cons.clear();
		solvcons.clear();
		var.clear();
		selrec.clear();

		auto build_vis = new BuildVisitor(cstate);
		//build expression tree
		expr_walk(build_vis,cblk->next_insmd);
		next_exinsmd = build_vis->get_expr(cblk->next_insmd);
		expr_walk(build_vis,cblk->mem);
		next_mem = build_vis->get_expr(cblk->mem);
		for(i = 0; i < ctx->NUMREG; i++) {
			expr_walk(build_vis,cblk->reg[i]);
			next_reg[i] =  build_vis->get_expr(cblk->reg[i]);
		}
		for(i = 0; i < ctx->NUMFLAG; i++) {
			expr_walk(build_vis,cblk->flag[i]);
			next_flag[i] = build_vis->get_cond(cblk->flag[i]);
		}
		selrec.insert(
			cstate->select_record.begin(),
			cstate->select_record.end());
		build_vis->get_mem_record(&selrec);
		delete build_vis;

		//initialize reg, flag, constraint
		expr_walk(trans_vis,next_exinsmd);
		expr_walk(trans_vis,next_mem);
		expr_iter_walk(trans_vis,next_reg,next_reg + ctx->NUMREG);
		expr_iter_walk(trans_vis,next_flag,next_flag + ctx->NUMFLAG);
		cons.insert(
			cstate->constraint.begin(),
			cstate->constraint.end());
		cons.insert(
			addrsp.mem_constraint.begin(),
			addrsp.mem_constraint.end());

		//initialize solver variable
		next_expc = next_reg[ctx->REGIDX_PC];
		var[next_exinsmd->solver_expr] = 0;

		for(i = 0; i < cstate->symbol.size(); i++) {
			expr_walk(trans_vis,cstate->symbol[i]);
			var[cstate->symbol[i]->solver_expr] = 0;
		}
		for(i = 0; i < addrsp.mem_symbol.size(); i++) {
			expr_walk(trans_vis,addrsp.mem_symbol[i].second);
			var[addrsp.mem_symbol[i].second->solver_expr] = 0;
		}
		for(auto it = selrec.begin(); it != selrec.end(); it++) {
			var[(*it)->oper->solver_expr] = 0;
			var[(*it)->idx->solver_expr] = 0;
		}

		while(true) {
			var[next_expc->solver_expr] = 0xdeadbeef;
			//Translate constraint
			expr_iter_walk(trans_vis,cons.begin(),cons.end());
			for(auto it = cons.begin(); it != cons.end(); it++) {
				solvcons.insert((*it)->solver_cond);
			}
			if(!solver->solve(solvcons,&var)) {
				break;	
			}
			next_rawpc = var[next_expc->solver_expr];
			next_insmd = var[next_exinsmd->solver_expr];

			//update address space
			bool addrsp_update = false;
			for(auto it = selrec.begin();
				it != selrec.end();
				it++
			) {
				auto selidx = var[(*it)->idx->solver_expr];
				//auto selval = var[(*it)->oper->solver_expr];
				//dbg("  sel: 0x%08lx\t0x%08lx\n",selidx,selval);
				if(addrsp.handle_select(
					selidx,(*it)->size) == 1
				) {
					addrsp_update = true;	
				}
			}
			if(addrsp_update) {
				cons.insert(
					addrsp.mem_constraint.begin(),
					addrsp.mem_constraint.end());
				for(i = 0; i < addrsp.mem_symbol.size(); i++) {
					auto sym = addrsp.mem_symbol[i].second;
					expr_walk(trans_vis,sym);
					var[sym->solver_expr] = 0;
				}
				continue;
			}

			draw.update_link(cstate->pc.rawpc,next_rawpc);

			//for "test" bound
			if(next_rawpc < 0x10000 || next_rawpc >= 0x20000) {
				dbg("0x%08lx touch bound, ignore\n",next_rawpc);
				exclude_pc(
					ctx,
					&cons,
					next_expc,
					next_exinsmd,
					next_rawpc,
					next_insmd);

				//show message
				info("next pc 0x%08lx\n",next_rawpc);
				for(i = 0; i < cstate->symbol.size(); i++) {
					info("  sym\t%d: 0x%08lx\n",
						cstate->symbol[i]->id,
						var[cstate->symbol[i]->solver_expr]);
				}
				for(i = 0; i < addrsp.mem_symbol.size(); i++) {
					info("  addr\t%d\t0x%08lx: 0x%08lx\n",
						addrsp.mem_symbol[i].second->id,
						addrsp.mem_symbol[i].first,
						var[addrsp.mem_symbol[i]. \
							second-> solver_expr]);
				}

				if(next_rawpc == 0xDEADBEEE) {
					continue;
				} else {
					dbg("exp\n");
					exp_flag = true;
					break;
				}
			}
			
			//create next state
			nstate = ref<State>(
				ProgCtr(next_rawpc,next_insmd),
				cstate->probe);
			nstate->mem = next_mem;
			for(i = 0; i < ctx->NUMREG; i++) {
				nstate->reg[i] = next_reg[i];
			}
			for(i = 0; i < ctx->NUMFLAG; i++) {
				nstate->flag[i] = next_flag[i];
			}
			nstate->constraint.insert(
				cstate->constraint.begin(),
				cstate->constraint.end());
			nstate->constraint.insert(create_pc_cond(
				ctx,
				next_expc,
				next_exinsmd,
				next_rawpc,
				next_insmd));
			nstate->symbol.assign(
				cstate->symbol.begin(),
				cstate->symbol.end());
			nstate->select_record.insert(
				selrec.begin(),
				selrec.end());

			exclude_pc(
				ctx,
				&cons,
				next_expc,
				next_exinsmd,
				next_rawpc,
				next_insmd);
			ctx->state.push(nstate);
		}
	}

	draw.output("flow.dot");

	delete trans_vis;
	return 0;
}

};
