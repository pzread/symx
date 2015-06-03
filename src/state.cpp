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
unsigned long maxlen = 0;

namespace symx {
    static std::unordered_map<uint64_t,unsigned long> block_length;
    static std::unordered_map<uint64_t,std::unordered_set<refState>> dep_state;
    class Compare {
	public:
	    bool operator() (const refState &a,const refState &b) {
		return a->length < b->length;
	    }
    };
    static std::priority_queue<refState,std::vector<refState>,Compare> worklist;

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

    int ActiveVisitor::pre_visit(const refBytVec &vec) {
	if(visited_exr.find(vec) != visited_exr.end()) {
	    return 0;
	}
	visited_exr.insert(vec);
	return 1;
    }
    int ActiveVisitor::pre_visit(const refBytMem &mem) {
	if(visited_exr.find(mem) != visited_exr.end()) {
	    return 0;
	}
	visited_exr.insert(mem);
	return 1;
    }
    int ActiveVisitor::pre_visit(const refOperator &oper) {
	if(visited_exr.find(oper) != visited_exr.end()) {
	    return 0;
	}
	visited_exr.insert(oper);
	return 1;
    }
    int ActiveVisitor::pre_visit(const refCond &cond) {
	if(visited_cond.find(cond) != visited_cond.end()) {
	    return 0;
	}
	visited_cond.insert(cond);
	return 1;
    }
    int ActiveVisitor::post_visit(const refBytVec &vec) {
	return 1;
    }
    int ActiveVisitor::post_visit(const refBytMem &mem) {
	return 1;
    }
    int ActiveVisitor::post_visit(const refOperator &oper) {
	unsigned int i;

	switch(oper->type) {
	    case ExprOpSelect:
		if(oper->operand[1]->type == ExprImm) {
		    auto addr = std::static_pointer_cast<BytVec>(
			    oper->operand[1]);
		    auto size = oper->size;

		    assert(size % 8 == 0);

		    auto mem_it = select.find(oper->operand[0]);
		    if(mem_it == select.end()) {
			mem_it = select.insert(std::make_pair(
				    oper->operand[0],
				    std::unordered_set<uint64_t>())).first;
		    }
		    for(i = 0; i < size / 8; i++) {
			select_addr.insert(addr->data + ((uint64_t)i));
			mem_it->second.insert(addr->data + ((uint64_t)i));
		    }
		}
		break;

	    case ExprOpStore:
		if(oper->operand[1]->type == ExprImm) {
		    auto addr = std::static_pointer_cast<BytVec>(
			    oper->operand[1]);
		    auto size = oper->operand[2]->size;

		    assert(size % 8 == 0);
		    
		    auto mem_it = store.find(oper->operand[0]);
		    if(mem_it == store.end()) {
			mem_it = store.insert(std::make_pair(
				    oper->operand[0],
				    std::unordered_set<uint64_t>())).first;
		    }
		    for(i = 0; i < size / 8; i++) {
			mem_it->second.insert(addr->data + ((uint64_t)i));
		    }
		}
		break;

	    default:
		break;
	}

	return 1;
    }
    int ActiveVisitor::post_visit(const refCond &cond) {
	return 1;
    }

    std::vector<refExpr> ActiveSolver::get_mem_layer(const refState &state) {
	refExpr mem = state->mem;
	std::vector<refExpr> ret;

	while(mem->type != ExprMem) {
	    ret.push_back(mem);
	    mem = std::static_pointer_cast<Operator>(mem)->operand[0];
	}
	ret.push_back(mem);

	std::reverse(ret.begin(),ret.end());
	return ret;
    }
    bool ActiveSolver::solve(
	    const refState &state,
	    const std::unordered_set<refCond> &target_constr,
	    const std::unordered_set<refCond> &constr,
	    std::unordered_map<refExpr,uint64_t> *concrete
    ) {
	ActiveVisitor inact_vis;
	std::unordered_set<refCond> act_constr;
	refAddrSpace as = state->as;

	inact_vis.iter_walk(target_constr.begin(),target_constr.end());
	for(auto it = concrete->begin(); it != concrete->end(); it++) {
	    inact_vis.walk(it->first);
	}

	/*
	auto mem_layer = get_mem_layer(state);
	for(i = 0; i < mem_layer.size(); i++) {
	    auto &mem = mem_layer[i];
	    auto sel_it = inact_vis.select.find(mem);
	    auto str_it = inact_vis.store.find(mem);

	    if(sel_it != inact_vis.select.end()) {
		for(
		    auto addr_it = sel_it->second.begin();
		    addr_it != sel_it->second.end();
		    addr_it++
		) {
		    auto addr = *addr_it;
		    dbg("sel %08lx\n",addr);
		}
	    }
	    if(str_it != inact_vis.store.end()) {
		for(
		    auto addr_it = str_it->second.begin();
		    addr_it != str_it->second.end();
		    addr_it++
		) {
		    auto addr = *addr_it;
		    dbg("str %08lx\n",addr);
		}
	    }
	    dbg("--------\n");
	}
	*/

	act_constr = target_constr;

	for(auto cond_it = constr.begin(); cond_it != constr.end(); cond_it++) {
	    ActiveVisitor outact_vis;

	    outact_vis.walk(*cond_it);

	    for(
		auto it = outact_vis.select_addr.begin();
		it != outact_vis.select_addr.end();
		it++
	    ) {
		auto addr = *it;

		if(as->mem_constr.find(*cond_it) == as->mem_constr.end()) {
		    if(as->mem_symbol.find(addr) ==
			    state->as->mem_symbol.end()) {
			continue;
		    }
		}

		if(inact_vis.select_addr.find(addr) !=
			inact_vis.select_addr.end()) {
		    act_constr.insert(*cond_it);
		    break;
		}
	    }
	}

	dbg("%d %d %d %d %d\n",target_constr.size(),state->select_set.size(),concrete->size(),constr.size(),act_constr.size());

	return solver->solve(act_constr,concrete);
    }

    refCond Executor::condition_pc(const refExpr &exrpc,const uint64_t rawpc) {
	return cond_eq(exrpc,BytVec::create_imm(exrpc->size,rawpc));
    }
    std::vector<refState> Executor::solve_state(
	    const refState cstate,
	    BuildVisitor *build_vis,
	    const refBlock cblk
    ) {
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
	std::unordered_set<refCond> target_constr;
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
	std::unordered_set<refMemRecord> tmp_selset;
	for(auto it = next_selset.begin(); it != next_selset.end(); it++) {
	    if((*it)->idx->type == ExprImm) {
		auto addr = std::static_pointer_cast<BytVec>((*it)->idx)->data;
		cas->handle_select(addr,(*it)->size);
	    } else {
		tmp_selset.insert(*it);
	    }
	}
	next_selset = tmp_selset;
	//merge old select record
	next_selset.insert(cstate->select_set.begin(),cstate->select_set.end());

	//initialize reg, flag, constraint
	constr.insert(jmp_cond);
	constr.insert(cstate->constr.begin(),cstate->constr.end());
	constr.insert(cas->mem_constr.begin(),cas->mem_constr.end());

	//initialize solver variable
	//TODO support instruction mode

	concrete[next_exrpc] = 0;
	/*for(i = 0; i < cstate->symbol.size(); i++) {
	    concrete[cstate->symbol[i]] = 0;
	}
	for(
	    auto it = cas->mem_symbol.begin();
	    it != cas->mem_symbol.end();
	    it++
	) {
	    concrete[it->second] = 0;
	}*/
	for(auto it = next_selset.begin(); it != next_selset.end(); it++) {
	    //concrete[(*it)->oper] = 0;
	    concrete[(*it)->idx] = 0;
	}
	for(auto it = next_strseq.begin(); it != next_strseq.end(); it++) {
	    //concrete[(*it)->oper->operand[2]] = 0;
	    concrete[(*it)->idx] = 0;
	}
	/*for(auto it = next_reg.begin(); it != next_reg.end(); it++) {
	    concrete[*it] = 0;
	}*/

	ActiveSolver *act_solver = new ActiveSolver(ctx->solver,cas);
	target_constr.insert(jmp_cond);

	while(true) {
	    //solve

	    if(!act_solver->solve(cstate,target_constr,constr,&concrete)) {
		break;	
	    }
	    next_rawpc = concrete[next_exrpc];

	    //handle dynamic select, update address space
	    bool as_update = false;
	    for(auto it = next_selset.begin(); it != next_selset.end(); it++) {
		auto addr = concrete[(*it)->idx];
		if(cas->handle_select(addr,(*it)->size) > 0) {
		    as_update = true;	
		}
	    }
	    if(as_update) {
		constr.insert(cas->mem_constr.begin(),cas->mem_constr.end());
		/*for(
		    auto it = cas->mem_symbol.begin();
		    it != cas->mem_symbol.end();
		    it++
		) {
		    concrete[it->second] = 0;
		}*/
		continue;
	    }

	    /*dbg("eip %016lx\n",next_rawpc);
	    dbg("eax %016lx\n",concrete[next_reg[REGIDX_EAX]]);
	    dbg("edx %016lx\n",concrete[next_reg[REGIDX_EDX]]);
	    dbg("zf %016lx\n",concrete[next_reg[REGIDX_ZF]]);

	    std::vector<std::pair<uint64_t,uint64_t>> tmpvec;
	    for(auto it = next_selset.begin(); it != next_selset.end(); it++) {
		tmpvec.push_back(std::make_pair(concrete[(*it)->idx],concrete[(*it)->oper]));
	    }
	    std::sort(tmpvec.begin(),tmpvec.end());
	    for(auto it = tmpvec.begin(); it != tmpvec.end(); it++) {
		dbg("ldr idx %016lx val %016lx\n",it->first,it->second);
	    }
	    tmpvec.clear();
	    for(auto it = next_strseq.begin(); it != next_strseq.end(); it++) {
		tmpvec.push_back(std::make_pair(concrete[(*it)->idx],concrete[(*it)->oper->operand[2]]));
	    }
	    std::sort(tmpvec.begin(),tmpvec.end());
	    for(auto it = tmpvec.begin(); it != tmpvec.end(); it++) {
		dbg("str idx %016lx val %016lx\n",it->first,it->second);
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

	    auto rawpc = nstate->pc.rawpc;

	    nstate->path = cstate->path;
	    nstate->path.push_back(rawpc);
	    nstate->blkmap = cstate->blkmap;

	    dep_state[rawpc].insert(nstate);

	    if(nstate->blkmap.find(rawpc) != nstate->blkmap.end()) {
		auto it = block_length.find(rawpc);
		if(it == block_length.end()) {
		    block_length[rawpc] = nstate->path.size() - nstate->blkmap[rawpc];
		} else {
		    it->second = std::max(it->second,nstate->path.size() - nstate->blkmap[rawpc]);
		}
		nstate->length = block_length[rawpc];
	    } else {
		nstate->blkmap[rawpc] = nstate->path.size();
		
		auto it = block_length.find(rawpc);
		if(it == block_length.end()) {
		    nstate->length = 0;
		} else {
		    nstate->length = it->second;
		}
	    }

	    maxlen = std::max(maxlen,nstate->path.size());
	    dbg("maxlen %lu\n",maxlen);
	    if(nstate->path.size() >= 1000) {
		for(
		    auto it = cas->mem_symbol.begin();
		    it != cas->mem_symbol.end();
		    it++
		) {
		    concrete[it->second] = 0;
		}
		ctx->solver->solve(constr,&concrete);

		for(unsigned int j = 0;j < nstate->path.size();j++) {
		    dbg("path %08lx\n",nstate->path[j]);
		}

		for(
		    auto it = cas->mem_symbol.begin();
		    it != cas->mem_symbol.end();
		    it++
		) {
		    dbg("mem symbol %08lx %x\n",it->first,concrete[it->second]);
		}

		dbg("long path %d\n",count);
		exit(0);
	    }

	    statelist.push_back(nstate);

	    target_constr.insert(cond_not(cond_pc));
	}

	delete act_solver;

	return statelist;
    }
    int Executor::execute() {
	uint64_t target_rawpc = 0x08048B7F;

	refSnapshot snap;
	std::unordered_map<ProgCtr,std::vector<refBlock> > block_cache;
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

	    dbg("length %u\n",cstate->length);

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

	    auto build_vis = new BuildVisitor(ctx->solver,cstate);

	    for(auto blkit = blklist.begin(); blkit != blklist.end(); blkit++) {
		auto statelist = solve_state(cstate,build_vis,*blkit);

		for(auto it = statelist.begin();
			it != statelist.end();
			it++
		) {
		    worklist.push(*it);
		}
	    }

	    delete build_vis;

	    /*if(cstate->pc.rawpc == 0x8048b69) {
		break;
	    }*/
	}

	ctx->destroy_vm(vm);
	return 0;
    }
};
