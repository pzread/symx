#define LOG_PREFIX "state"

#include<assert.h>
#include<vector>
#include<memory>
#include<unordered_map>
#include<algorithm>
#include<capstone/capstone.h>

#include"utils.h"
#include"context.h"
#include"expr.h"
#include"state.h"
#include"solver/z3.h"

using namespace symx;

int count = 0;

namespace symx {

    bool Block::operator<(const Block& other) const {
	return length > other.length;
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
		store_seq.push_back(ref<MemRecord>(
			    std::static_pointer_cast<Operator>(expr_map[oper]),
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
		    auto strseq = addrsp->source_select(oper,var);
		    if(strseq.size() == 0) {
			auto idx_it = var.find(oper->operand[1]);
			assert(idx_it != var.end());
			if(addrsp->mem_symbol.find(idx_it->second) != addrsp->mem_symbol.end()) {
			    fix = false;
			}
		    } else {
			for(
				auto it = strseq.begin();
				it != strseq.end();
				it++
			) {
			    walk((*it)->operand[1]);
			    walk((*it)->operand[2]);
			    fix = fix_expr[(*it)->operand[1]] &
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

    Executor::Executor(Context *_ctx) : ctx(_ctx) {
	trans_vis = ctx->solver->create_translator();
    }
    Executor::~Executor() {
	delete trans_vis;
    }
    refCond Executor::condition_pc(const refExpr &exrpc,const uint64_t rawpc) {
	return cond_eq(exrpc,BytVec::create_imm(exrpc->size,rawpc));
    }
    std::vector<refState> Executor::solve_state(
	    const refState cstate,
	    BuildVisitor *build_vis,
	    const refBlock cblk
    ) {
	unsigned int i;
	std::vector<refState> statelist;

	refAddrSpace cas;
	refCond jmp_cond;
	refExpr next_exrpc;
	uint64_t next_rawpc;
	refExpr next_mem;
	std::vector<refExpr> next_reg;
	std::vector<refCond> next_flag;
	std::unordered_set<refMemRecord> next_selset;
	std::vector<refMemRecord> next_strseq;
	std::unordered_set<refCond> constr;
	std::unordered_map<refExpr,uint64_t> concrete;
	refState nstate;
	
	//initialize environment
	statelist.clear();
	cas = cstate->as;
	next_reg.clear();
	next_flag.clear();
	next_selset.clear();
	next_strseq.clear();
	constr.clear();
	concrete.clear();

	build_vis->walk(cblk->cond);
	jmp_cond = build_vis->get_cond(cblk->cond);
	build_vis->walk(cblk->nextpc);
	next_exrpc = build_vis->get_expr(cblk->nextpc);
	build_vis->walk(cblk->mem);
	next_mem = build_vis->get_expr(cblk->mem);
	for(auto it = cblk->reg.begin(); it != cblk->reg.end(); it++) {
	    build_vis->walk(*it);
	    next_reg.push_back(build_vis->get_expr(*it));
	}
	for(auto it = cblk->flag.begin(); it != cblk->flag.end(); it++) {
	    build_vis->walk(*it);
	    next_flag.push_back(build_vis->get_cond(*it));
	}
	next_selset = cstate->select_set;
	next_strseq = cstate->store_seq;
	build_vis->get_mem_record(&next_selset,&next_strseq);   

	//initialize reg, flag, constraint
	trans_vis->walk(jmp_cond);
	trans_vis->walk(next_exrpc);
	trans_vis->walk(next_mem);
	trans_vis->iter_walk(next_reg.begin(),next_reg.end());
	trans_vis->iter_walk(next_flag.begin(),next_flag.end());
	constr.insert(jmp_cond);
	constr.insert(cstate->constr.begin(),cstate->constr.end());
	constr.insert(cas->mem_constr.begin(),cas->mem_constr.end());

	//initialize solver variable
	//TODO support instruction mode

	concrete[next_exrpc] = 0;
	for(i = 0; i < cstate->symbol.size(); i++) {
	    trans_vis->walk(cstate->symbol[i]);
	    concrete[cstate->symbol[i]] = 0;
	}
	for(
		auto it = cas->mem_symbol.begin();
		it != cas->mem_symbol.end();
		it++
	   ) {
	    trans_vis->walk(it->second);
	    concrete[it->second] = 0;
	}
	for(auto it = next_selset.begin(); it != next_selset.end(); it++) {
	    concrete[(*it)->oper] = 0;
	    concrete[(*it)->idx] = 0;
	}
	for(auto it = next_strseq.begin(); it != next_strseq.end(); it++) {
	    concrete[(*it)->oper->operand[2]] = 0;
	    concrete[(*it)->idx] = 0;
	}
	for(auto it = next_reg.begin(); it != next_reg.end(); it++) {
	    concrete[*it] = 0;
	}

	concrete[next_reg[REGIDX_ECX]] = 0;
	concrete[next_reg[REGIDX_ESP]] = 0;

	while(true) {
	    //translate constraint
	    trans_vis->iter_walk(constr.begin(),constr.end());

	    //solve
	    if(!ctx->solver->solve(constr,&concrete)) {
		break;	
	    }
	    next_rawpc = concrete[next_exrpc];

	    //update address space
	    bool as_update = false;
	    for(auto it = next_selset.begin(); it != next_selset.end(); it++) {
		auto selidx = concrete[(*it)->idx];
		if(cas->handle_select(selidx,(*it)->size) > 0) {
		    as_update = true;	
		}
	    }
	    if(as_update) {
		constr.insert(cas->mem_constr.begin(),cas->mem_constr.end());
		for(
			auto it = cas->mem_symbol.begin();
			it != cas->mem_symbol.end();
			it++
		) {
		    trans_vis->walk(it->second);
		    concrete[it->second] = 0;
		}
		continue;
	    }

	    dbg("eip %016lx\n",next_rawpc);
	    dbg("ecx %016lx\n",concrete[next_reg[REGIDX_ECX]]);
	    dbg("esp %016lx\n",concrete[next_reg[REGIDX_ESP]]);
	    dbg("zf %016lx\n",concrete[next_reg[REGIDX_ZF]]);
	    for(auto it = next_selset.begin(); it != next_selset.end(); it++) {
		dbg("ldr idx %016lx val %016lx\n",concrete[(*it)->idx],concrete[(*it)->oper]);
	    }
	    for(auto it = next_strseq.begin(); it != next_strseq.end(); it++) {
		dbg("str idx %016lx val %016lx\n",concrete[(*it)->idx],concrete[(*it)->oper->operand[2]]);
	    }

	    auto fix_vis = new FixVisitor(cas,concrete);
	    for(auto it = next_reg.begin(); it != next_reg.end(); it++) {
		fix_vis->walk(*it);
		if(fix_vis->get_fix(*it)) {
		    *it = BytVec::create_imm((*it)->size,concrete[*it]);
		}
	    }
	    delete fix_vis;

	    auto cond_pc = condition_pc(next_exrpc,next_rawpc);
	    nstate = ref<State>(
		    ProgCtr(next_rawpc,CS_MODE_32),
		    cas,
		    next_mem,
		    next_reg,
		    next_flag);
	    nstate->constr = constr;
	    nstate->constr.insert(cond_pc);
	    nstate->select_set = next_selset;
	    nstate->store_seq = next_strseq;

	    nstate->path = cstate->path;
	    nstate->path.push_back(cblk);

	    if(nstate->path.size() > 50) {
		err("long path %d\n",count);
	    }

	    statelist.push_back(nstate);
	    constr.insert(cond_not(cond_pc));
	}

	return statelist;
    }
    int Executor::execute() {
	unsigned int i;
	uint64_t target_rawpc = 0x08048aac;

	refSnapshot snap;
	std::unordered_map<ProgCtr,std::vector<refBlock> > block_cache;
	std::priority_queue<refState> worklist;
	//std::queue<refState> worklist;
	refState nstate,cstate;
	std::vector<refBlock> blklist;
	refBlock cblk;
	
	//Create base component
	VirtualMachine *vm = ctx->create_vm();

	//Get main entry snapshot
	if(vm->event_wait() != VMCOM_EVT_ENTER) {
	    err("unexpected event\n");
	}
	vm->event_ret();
	while(vm->event_wait() == VMCOM_EVT_EXECUTE) {
	    dbg("%08lx\n",vm->event_get_pc());
	    if(vm->event_get_pc() == target_rawpc) {
		info("find main entry\n");
		break;
	    }
	    vm->event_ret();
	}
	snap = vm->event_suspend();

	auto base_as = ref<AddrSpace>(ctx,snap);
	nstate = ref<State>(
		ProgCtr(target_rawpc,CS_MODE_32),
		base_as,
		base_as->mem,
		snap->reg,
		snap->flag);
	worklist.push(nstate);

	while(!worklist.empty()) {
	    cstate = worklist.top();
	    //cstate = worklist.front();
	    worklist.pop();
	    info("\e[1;32mrun state 0x%016lx\e[m\n",cstate->pc.rawpc);

	    count++;

	    auto blklist_it = block_cache.find(cstate->pc);
	    if(blklist_it == block_cache.end()) {
		blklist = snap->translate_bb(cstate->pc);
		if(blklist.size() == 0) {
		    continue;
		}
		block_cache[cstate->pc] = blklist;
	    } else {
		blklist = blklist_it->second;
	    }

	    auto build_vis = new BuildVisitor(cstate);

	    for(auto blkit = blklist.begin(); blkit != blklist.end(); blkit++) {
		auto statelist = solve_state(cstate,build_vis,*blkit);

		if(statelist.size() == 0) {
		    for(i = 0; i < cstate->path.size(); i++) {
			auto blk = cstate->path[i];
			blk->length = std::max(
				blk->length,
				(int)(cstate->path.size() - i));
		    }
		} else {
		    for(auto it = statelist.begin(); it != statelist.end(); it++) {
			worklist.push(*it);
		    }
		}
	    }

	    delete build_vis;
	}

	ctx->destroy_vm(vm);
	return 0;
    }

    /*
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
    refExpr next_exrpc;
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


	while(true) {
	    next_rawpc = var[next_exrpc];
	    next_insmd = var[next_exinsmd];


	    draw.update_link(cstate->pc.rawpc,next_rawpc);

	    //for "test" bound
	    if(next_rawpc < 0x10000 || next_rawpc >= 0x20000) {
		dbg("0x%08lx touch bound, ignore\n",next_rawpc);
		exclude_pc(
			ctx,
			&cons,
			next_exrpc,
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
			next_exrpc,
			next_exinsmd,
			next_rawpc,
			next_insmd));
	    nstate->symbol = cstate->symbol;
	    nstate->select_set = selset;
	    nstate->store_seq = strseq;

	    exclude_pc(
		    ctx,
		    &cons,
		    next_exrpc,
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
