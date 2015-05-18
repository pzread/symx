#define LOG_PREFIX "state"

#include<memory>
#include<string>
#include<unordered_map>
#include<vector>
#include<bitset>
#include<capstone/capstone.h>

#include"utils.h"
#include"context.h"
#include"expr.h"
#include"state.h"

using namespace symx;

namespace symx {
    int state_executor(Context *ctx) {
	uint64_t target_rawpc = 0x080483FB;

	refSnapshot snap;
	std::queue<refState> worklist;
	std::unordered_map<ProgCtr,refBlock> block_cache;
	refState nstate,cstate;
	refBlock cblk;

	//Create base VM
	VirtualMachine *vm = ctx->create_vm();

	//Get main entry snapshot
	if(vm->event_wait() != VMCOM_EVT_ENTER) {
	    err("unexpected event\n");
	}
	vm->event_ret();
	while(vm->event_wait() == VMCOM_EVT_EXECUTE) {
	    if(vm->event_get_pc() == target_rawpc) {
		info("find main entry\n");
		break;
	    }
	    vm->event_ret();
	}
	snap = vm->event_suspend();

	nstate = ref<State>(
		ProgCtr(target_rawpc,CS_MODE_32),
		ref<AddrSpace>(ctx,snap));
	worklist.push(nstate);

	while(!worklist.empty()) {
	    cstate = worklist.back();
	    worklist.pop();
	    info("\e[1;32mrun state 0x%016lx\e[m\n",cstate->pc);

	    auto blk_it = block_cache.find(cstate->pc);
	    if(blk_it == block_cache.end()) {
		cblk = snap->translate_bb(cstate->pc);
		block_cache[cstate->pc] = cblk;
	    } else {
		cblk = blk_it->second;
	    }
	}

	ctx->destroy_vm(vm);
	return 0;
    }

/*AddrSpace::AddrSpace(
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
				page.symbol.reset(off);
			} else {
				//for test
				//val = BytVec::create_imm(1,1);
				val = BytVec::create_var(1,ctx);
				mem_symbol[pos] = val;
				page.symbol.set(off);
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
std::vector<refOperator> AddrSpace::source_select(
	const refOperator &sel,
	const std::unordered_map<refExpr,uint64_t> &var
) const {
	std::vector<refOperator> retseq;
	refExpr mem;
	uint64_t base;
	uint64_t idx;

	assert(sel->type == ExprOpSelect);

	auto base_it = var.find(sel->operand[1]);
	assert(base_it != var.end());
	mem = sel->operand[0];
	base = base_it->second;

	while(mem->type != ExprMem) {
		assert(mem->type == ExprOpStore);
		auto str = std::static_pointer_cast<Operator>(mem);
		auto idx_it = var.find(str->operand[1]);
		assert(idx_it != var.end());
		idx = idx_it->second;

		if(idx == base) {
			retseq.push_back(str);
			break;
		}

		mem = str->operand[0];
	}
	
	return retseq;
}
refExpr BuildVisitor::get_expr(const refExpr &expr) {
	auto it = expr_map.find(expr);
	if(it == expr_map.end()) {
		err("expr not exist\n");
		return nullptr;
	}
	return it->second;
}
refCond BuildVisitor::get_cond(const refCond &cond) {
	auto it = cond_map.find(cond);
	if(it == cond_map.end()) {
		err("cond not exist\n");
		return nullptr;
	}
	return it->second;
}
int BuildVisitor::get_mem_record(
	std::unordered_set<refMemRecord> *selset,
	std::vector<refMemRecord> *strseq
) {
	selset->insert(select_set.begin(),select_set.end());
	strseq->insert(strseq->end(),store_seq.begin(),store_seq.end());
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
		select_set.insert(ref<MemRecord>(
			std::static_pointer_cast<Operator>(expr_map[oper]),
			mem,
			idx,
			oper->size));
		break;
	}
	case ExprOpStore:
	{
		auto mem = expr_map[oper->operand[0]];
		auto idx = expr_map[oper->operand[1]];
		auto val = expr_map[oper->operand[2]];
		expr_map[oper] = expr_store(mem,idx,val);
		store_seq.push_back(ref<MemRecord>
			(std::static_pointer_cast<Operator>(expr_map[oper]),
			mem,
			idx,
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

bool FixVisitor::get_fix(const refExpr &expr) {
	auto log_it = fix_expr.find(expr);
	assert(log_it != fix_expr.end());
	return log_it->second;
}
int FixVisitor::pre_visit(const refBytVec &vec) {
	if(fix_expr.find(vec) != fix_expr.end()) {
		return 0;
	}
	return 1;
}
int FixVisitor::pre_visit(const refBytMem &mem) {
	if(fix_expr.find(mem) != fix_expr.end()) {
		return 0;
	}
	return 1;
}
int FixVisitor::pre_visit(const refOperator &oper) {
	if(fix_expr.find(oper) != fix_expr.end()) {
		return 0;
	}
	return 1;
}
int FixVisitor::pre_visit(const refCond &cond) {
	return 0;
}
int FixVisitor::post_visit(const refBytVec &vec) {
	if(vec->type == ExprVar) {
		fix_expr[vec] = false;
		return 1;
	}
	fix_expr[vec] = true;
	return 1;
}
int FixVisitor::post_visit(const refBytMem &mem) {
	fix_expr[mem] = true;
	return 1;
}
int FixVisitor::post_visit(const refOperator &oper) {
	switch(oper->type) {
	case ExprOpSelect:
	{
		bool fix = fix_expr[oper->operand[1]];
		if(fix) {
			auto strseq = addrsp.source_select(oper,var);
			if(strseq.size() == 0) {
				auto idx_it = var.find(oper->operand[1]);
				assert(idx_it != var.end());
				if(addrsp.mem_symbol.find(
					idx_it->second
				) != addrsp.mem_symbol.end()) {
					fix = false;
				}
			} else {
				for(
					auto it = strseq.begin();
					it == strseq.end();
					it++
				) {
					expr_walk(this,(*it)->operand[1]);
					expr_walk(this,(*it)->operand[2]);
					fix = fix_expr[(*it)->operand[1]] |
						fix_expr[(*it)->operand[2]];
				}
			}
		}
		fix_expr[oper] = fix;
		break;
	}
	case ExprOpIte:
		fix_expr[oper] = false;
		break;
	default:
	{
		unsigned int i;
		bool fix = true;
		for(i = 0; i < oper->op_count; i++) {
			fix &= fix_expr[oper->operand[i]];
		}
		fix_expr[oper] = fix;
		break;
	}
	}
	return 1;
}
int FixVisitor::post_visit(const refCond &cond) {
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
static int show_message(
	const uint64_t rawpc,
	std::unordered_map<refExpr,uint64_t> &var,
	const std::vector<refBytVec> &symbol,
	const std::unordered_map<uint64_t,refBytVec> &mem_symbol
) {
	unsigned int i;

	info("next pc 0x%08lx\n",rawpc);
	for(i = 0; i < symbol.size(); i++) {
		info("  sym%d: 0x%08lx\n",symbol[i]->id,var[symbol[i]]);
	}
	for(
		auto it = mem_symbol.begin();
		it != mem_symbol.end();
		it++
	) {
		info("  addr\t%d\t0x%08lx: 0x%08lx\n",
			it->second->id,
			it->first,
			var[it->second]);
	}
	return 0;
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
	std::unordered_map<refExpr,uint64_t> var;
	refExpr next_expc;
	refExpr next_exinsmd;
	refExpr next_mem;
	refExpr next_reg[256];
	refCond next_flag[64];
	uint64_t next_rawpc;
	int next_insmd;
	std::unordered_set<refMemRecord> selset;
	std::vector<refMemRecord> strseq;

	auto draw = Draw();
	bool find_flag = false;

	Backward backward;

	nstate = create_static_state(ctx,probe,addrsp,entry_rawpc);
	ctx->state.push(nstate);

	trans_vis = solver->create_translator();
	while(!ctx->state.empty() && !find_flag) {
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

		//backward
		backward.check_point(cblk->reg[ctx->REGIDX_PC]);
		
		//initialize
		cons.clear();
		var.clear();
		selset = cstate->select_set;
		strseq = cstate->store_seq;

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
		build_vis->get_mem_record(&selset,&strseq);
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
		var[next_expc] = 0;
		var[next_exinsmd] = 0;

		for(i = 0; i < cstate->symbol.size(); i++) {
			expr_walk(trans_vis,cstate->symbol[i]);
			var[cstate->symbol[i]] = 0;
		}
		for(
			auto it = addrsp.mem_symbol.begin();
			it != addrsp.mem_symbol.end();
			it++
		) {
			expr_walk(trans_vis,it->second);
			var[it->second] = 0;
		}
		for(auto it = selset.begin(); it != selset.end(); it++) {
			var[(*it)->oper] = 0;
			var[(*it)->idx] = 0;
		}
		for(auto it = strseq.begin(); it != strseq.end(); it++) {
			var[(*it)->idx] = 0;
		}
		for(i = 0; i < ctx->NUMREG; i++) {
			var[next_reg[i]] = 0;
		}

		while(true) {
			//Translate constraint
			expr_iter_walk(trans_vis,cons.begin(),cons.end());

			if(!solver->solve(cons,&var)) {
				break;	
			}
			next_rawpc = var[next_expc];
			next_insmd = var[next_exinsmd];

			//update address space
			bool addrsp_update = false;
			for(
				auto it = selset.begin();
				it != selset.end();
				it++
			) {
				auto selidx = var[(*it)->idx];
				if(addrsp.handle_select(
					selidx,
					(*it)->size
				) == 1) {
					addrsp_update = true;	
				}
			}
			if(addrsp_update) {
				cons.insert(
					addrsp.mem_constraint.begin(),
					addrsp.mem_constraint.end());
				for(
					auto it = addrsp.mem_symbol.begin();
					it != addrsp.mem_symbol.end();
					it++
				) {
					expr_walk(trans_vis,it->second);
					var[it->second] = 0;
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

				show_message(
					next_rawpc,
					var,
					cstate->symbol,
					addrsp.mem_symbol);

				if(next_rawpc == 0xDEADBEEE) {
					continue;
				} else {
					dbg("find\n");
					find_flag = true;
					break;
				}
			}

			//create next state
			nstate = ref<State>(
				ProgCtr(next_rawpc,next_insmd),
				cstate->probe);
			nstate->mem = next_mem;
			for(i = 0; i < ctx->NUMFLAG; i++) {
				nstate->flag[i] = next_flag[i];
			}

			FixVisitor fixvis = FixVisitor(addrsp,var);
			for(i = 0; i < ctx->NUMREG; i++) {
				expr_walk(&fixvis,next_reg[i]);
				if(fixvis.get_fix(next_reg[i])) {
					nstate->reg[i] = BytVec::create_imm(
						ctx->REGSIZE,
						var[next_reg[i]]);
				} else {
					nstate->reg[i] = next_reg[i];
				}
			}
			
			nstate->constraint = cstate->constraint;
			nstate->constraint.insert(create_pc_cond(
				ctx,
				next_expc,
				next_exinsmd,
				next_rawpc,
				next_insmd));
			nstate->symbol = cstate->symbol;
			nstate->select_set = selset;
			nstate->store_seq = strseq;

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
}*/

};
