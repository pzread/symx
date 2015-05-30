#define LOG_PREFIX "state"

#include<assert.h>
#include<vector>
#include<memory>
#include<unordered_map>
#include<algorithm>
#include<bitset>
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
	refExpr bldexr;

	switch(oper->type) {
	    case ExprOpSelect:
	    {
		auto mem = expr_map[oper->operand[0]];
		auto idx = expr_map[oper->operand[1]];
		bldexr = expr_select(mem,idx,oper->size);
		break;
	    }
	    case ExprOpStore:
	    {
		auto mem = expr_map[oper->operand[0]];
		auto idx = expr_map[oper->operand[1]];
		auto val = expr_map[oper->operand[2]];
		bldexr = expr_store(mem,idx,val);
		break;
	    }
	    case ExprOpExtract:
		bldexr = expr_extract(
			expr_map[oper->operand[0]],
			oper->start,
			oper->start + oper->size);
		break;

	    case ExprOpIte:
		bldexr = expr_ite(
			cond_map[oper->cond],
			expr_map[oper->operand[0]],
			expr_map[oper->operand[1]]);
		break;

	    default:
		if(oper->op_count == 1) {
		    bldexr = ref<Operator>(
			    oper->type,
			    oper->size,
			    expr_map[oper->operand[0]]);
		} else if(oper->op_count == 2) {
		    bldexr = ref<Operator>(
			    oper->type,
			    oper->size,
			    expr_map[oper->operand[0]],
			    expr_map[oper->operand[1]]);
		} else if(oper->op_count == 3) {
		    bldexr = ref<Operator>(
			    expr_map[oper->operand[0]],
			    expr_map[oper->operand[1]],
			    expr_map[oper->operand[2]]);
		}
		break;
	}

	bldexr = solid_operator(std::static_pointer_cast<Operator>(bldexr));

	if(bldexr->type == ExprOpSelect) {
	    auto bldoper = std::static_pointer_cast<Operator>(bldexr);
	    select_set.insert(ref<MemRecord>(
			bldoper,
			bldoper->operand[0],
			bldoper->operand[1],
			oper->size));
	} else if(oper->type == ExprOpStore) {
	    auto bldoper = std::static_pointer_cast<Operator>(bldexr);
	    store_seq.push_back(ref<MemRecord>(
			bldoper,
			bldoper->operand[0],
			bldoper->operand[1],
			oper->size));
	}

	expr_map[oper] = bldexr;
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
    refExpr BuildVisitor::solid_operator(const refOperator &oper) {
	refExpr retexr = oper;
	std::unordered_set<refCond> constr;
	std::unordered_map<refExpr,uint64_t> concrete;

	switch(oper->type) {
	    case ExprOpSelect:
		//retexr = solid_mem_read(oper);
		break;
	    case ExprOpStore:
		break;
	    case ExprOpExtract:
		if(oper->operand[0]->type == ExprImm) {
		    concrete[oper] = 0;
		    if(solver->solve(constr,&concrete)) {
			retexr = BytVec::create_imm(oper->size,concrete[oper]);
		    }
		}
		break;
	    case ExprOpIte:
		break;
	    default:
	    {
		unsigned int i;
		bool solid = true;

		for(i = 0; i < oper->op_count; i++) {
		    if(oper->operand[i]->type != ExprImm) {
			solid = false;
		    }
		}
		if(solid) {
		    concrete[oper] = 0;
		    if(solver->solve(constr,&concrete)) {
			retexr = BytVec::create_imm(oper->size,concrete[oper]);
		    }
		}
		break;
	    }
	}

	return retexr;
    }
    refExpr BuildVisitor::solid_mem_read(const refOperator &oper) {
	refExpr retexr = oper;
	unsigned int i;
	refExpr memexr;
	uint64_t addr;
	unsigned int size;
	int *bitmap;
	std::unordered_set<refCond> constr;
	std::unordered_map<refExpr,uint64_t> concrete;

	assert(oper->type == ExprOpSelect);

	if(oper->operand[1]->type != ExprImm) {
	    return retexr;
	}

	addr = std::static_pointer_cast<BytVec>(oper->operand[1])->data;
	size = oper->size;
	memexr = oper->operand[0];

	bitmap = new int[size];
	for(i = 0; i < size; i++) {
	    bitmap[i] = 0;
	}

	//TODO O(N^2) -> O(N)
	while(memexr->type != ExprMem) {
	    auto strexr = std::static_pointer_cast<Operator>(memexr);

	    if(strexr->operand[1]->type != ExprImm) {
		break;
	    }

	    auto straddr = std::static_pointer_cast<BytVec>(
		    strexr->operand[1])->data;
	    auto start = std::max(straddr,addr);
	    auto end = std::min(straddr + strexr->operand[2]->size,addr + size);
	    
	    if(start < end) {
		int val = 0;
		if(strexr->operand[2]->type != ExprImm) {
		    val = 1;
		} else {
		    val = 2;
		}
		for(i = start; i < end; i++) {
		    bitmap[i - addr] = std::max(bitmap[i - addr],val);
		}
	    }

	    memexr = strexr->operand[0];
	}
	if(memexr->type == ExprMem) {
	    for(i = 0; i < size; i++) {
		if(bitmap[i] != 2) {
		    break;
		}
	    }
	    if(i == size) {
		concrete[oper] = 0;
		if(solver->solve(constr,&concrete)) {
		    retexr = BytVec::create_imm(oper->size,concrete[oper]);
		}
	    }
	}

	delete bitmap;

	return retexr;
    }

    /*
    int SolidFixVisitor::pre_visit(const refBytVec &vec) {
	if(visited.find(vec) != visited.end()) {
	    return 0;
	}
	visited.insert(vec);
	return 1;
    }
    int SolidFixVisitor::pre_visit(const refBytMem &mem) {
	if(visited.find(mem) != visited.end()) {
	    return 0;
	}
	visited.insert(mem);
	return 1;
    }
    int SolidFixVisitor::pre_visit(const refOperator &oper) {
	if(visited.find(oper) != visited.end()) {
	    return 0;
	}
	visited.insert(oper);
	return 1;
    }
    int SolidFixVisitor::pre_visit(const refCond &cond) {
	//TODO handle Cond
	return 0;
    }
    int SolidFixVisitor::post_visit(const refBytVec &vec) {
	if(vec->type == ExprImm) {
	    state->fix_exr[vec] = vec->data;
	}
	return 1;
    }
    int SolidFixVisitor::post_visit(const refBytMem &mem) {
	state->fix_exr[mem] = 0;
	return 1;
    }
    int SolidFixVisitor::post_visit(const refOperator &oper) {
	switch(oper->type) {
	    case ExprOpSelect:
	    {
		bool fix = fix_expr[oper->operand[1]];
		if(state) {
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
    */

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
	std::vector<uint64_t> solid_seladdr;
	
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
	solid_seladdr.clear();

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

	//copy old store record
	next_strseq = cstate->store_seq;
	//get memory record
	build_vis->get_mem_record(&next_selset,&next_strseq);   
	//handle solid select address
	for(auto it = next_selset.begin(); it != next_selset.end(); it++) {
	    if((*it)->idx->type == ExprImm) {
		auto addr = std::static_pointer_cast<BytVec>((*it)->idx)->data;
		cas->handle_select(addr,(*it)->size);
	    }
	}
	//merge old select record
	next_selset.insert(cstate->select_set.begin(),cstate->select_set.end());

	//initialize reg, flag, constraint
	constr.insert(jmp_cond);
	constr.insert(cstate->constr.begin(),cstate->constr.end());
	constr.insert(cas->mem_constr.begin(),cas->mem_constr.end());

	//initialize solver variable
	//TODO support instruction mode

	concrete[next_exrpc] = 0;
	for(i = 0; i < cstate->symbol.size(); i++) {
	    concrete[cstate->symbol[i]] = 0;
	}
	for(
		auto it = cas->mem_symbol.begin();
		it != cas->mem_symbol.end();
		it++
	) {
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
		    concrete[it->second] = 0;
		}
		count++;
		continue;
	    }

	    /*dbg("eip %016lx\n",next_rawpc);
	    dbg("ecx %016lx\n",concrete[next_reg[REGIDX_ECX]]);
	    dbg("esp %016lx\n",concrete[next_reg[REGIDX_ESP]]);
	    dbg("zf %016lx\n",concrete[next_reg[REGIDX_ZF]]);
	    for(auto it = next_selset.begin(); it != next_selset.end(); it++) {
		dbg("ldr idx %016lx val %016lx\n",concrete[(*it)->idx],concrete[(*it)->oper]);
	    }
	    for(auto it = next_strseq.begin(); it != next_strseq.end(); it++) {
		dbg("str idx %016lx val %016lx\n",concrete[(*it)->idx],concrete[(*it)->oper->operand[2]]);
	    }*/

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

	    if(nstate->path.size() > 10) {
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

	    auto build_vis = new BuildVisitor(ctx->solver,cstate);

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
		    for(auto it = statelist.begin();
			    it != statelist.end();
			    it++
		    ) {
			worklist.push(*it);
		    }
		}
	    }

	    delete build_vis;
	}

	ctx->destroy_vm(vm);
	return 0;
    }

};
