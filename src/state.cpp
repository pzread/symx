#define LOG_PREFIX "state"

#include<assert.h>
#include<vector>
#include<memory>
#include<bitset>
#include<unordered_map>
#include<unordered_set>
#include<algorithm>
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
    class Compare {
	public:
	    bool operator() (const refState &a,const refState &b) {
                if(a->length != 0 && b->length != 0) {
		    return a->length < b->length;
                }
                if(a->length == 0) {
                    return false;
                }
                return true;
	    }
    };
    static std::priority_queue<refState,std::vector<refState>,Compare> worklist;
    //static std::queue<refState> worklist;

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
    const std::unordered_set<refMemRecord>& BuildVisitor::get_mem_record() {
        return select_set;
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

	bldexr = solid_operator(
                std::static_pointer_cast<const Operator>(bldexr));

	if(bldexr->type == ExprOpSelect) {
	    auto bldoper = std::static_pointer_cast<const Operator>(bldexr);
	    select_set.insert(ref<MemRecord>(
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
		retexr = solid_mem_read(oper);

                assert(retexr->size == oper->size);

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
        uint64_t addr;
        unsigned int size;
        refExpr tmpexr;

	assert(oper->type == ExprOpSelect);

	if(oper->operand[1]->type != ExprImm) {
	    return oper;
	}
        addr = std::static_pointer_cast<const BytVec>(oper->operand[1])->data;
        size = oper->size;

        tmpexr = oper->operand[0];
        while(tmpexr->type != ExprMem) {
            auto strexr = std::static_pointer_cast<const Operator>(tmpexr);
            if(strexr->operand[1]->type != ExprImm) {
                return oper;
            }
            if(
                addr == std::static_pointer_cast<const BytVec>(
                    strexr->operand[1])->data &&
                size == strexr->operand[2]->size
            ) {
                return strexr->operand[2];
            }
            tmpexr = strexr->operand[0];
        }
	return oper;

	/*addr = std::static_pointer_cast<BytVec>(oper->operand[1])->data;
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

	delete bitmap;*/
    }

    const std::vector<uint64_t>& ActiveVisitor::get_expr_addr(
            const refExpr &expr
    ) {
        auto it = cache_expr.find(expr);

        assert(it != cache_expr.end());

        return it->second;
    }
    const std::vector<uint64_t>& ActiveVisitor::get_cond_addr(
            const refCond &cond
    ) {
        auto it = cache_cond.find(cond);

        assert(it != cache_cond.end());

        return it->second;
    }
    int ActiveVisitor::pre_visit(const refBytVec &vec) {
	if(cache_expr.find(vec) != cache_expr.end()) {
	    return 0;
	}
	return 1;
    }
    int ActiveVisitor::pre_visit(const refBytMem &mem) {
	if(cache_expr.find(mem) != cache_expr.end()) {
	    return 0;
	}
	return 1;
    }
    int ActiveVisitor::pre_visit(const refOperator &oper) {
	if(cache_expr.find(oper) != cache_expr.end()) {
	    return 0;
	}
	return 1;
    }
    int ActiveVisitor::pre_visit(const refCond &cond) {
	if(cache_cond.find(cond) != cache_cond.end()) {
	    return 0;
	}
	return 1;
    }
    int ActiveVisitor::post_visit(const refBytVec &vec) {
	cache_expr[vec] = {};
	return 1;
    }
    int ActiveVisitor::post_visit(const refBytMem &mem) {
        cache_expr[mem] = {};
	return 1;
    }
    int ActiveVisitor::post_visit(const refOperator &oper) {
	unsigned int i;

        auto cache_set = &cache_expr.insert(
                std::make_pair(oper,std::vector<uint64_t>())).first->second;
        for(i = 0; i < oper->op_count; i++) {
            auto it = cache_expr.find(oper->operand[i]);

            assert(it != cache_expr.end());

            cache_set->insert(
                    cache_set->end(),
                    it->second.begin(),
                    it->second.end());
        }

        if(oper->type == ExprOpIte) {
            auto it = cache_cond.find(oper->cond);

            assert(it != cache_cond.end());

            cache_set->insert(
                    cache_set->end(),
                    it->second.begin(),
                    it->second.end());
        }

        if(oper->type == ExprOpSelect && oper->operand[1]->type == ExprImm) {
	    auto immexr = std::static_pointer_cast<const BytVec>(
                    oper->operand[1]);

            if(immexr->data < 0x2000) {
                err("test\n");
            }

            for(i = 0; i < oper->size / 8; i++) {
                cache_set->insert(cache_set->end(),immexr->data + (uint64_t)i);
            }
        }

        std::sort(cache_set->begin(),cache_set->end());
        auto last_it = std::unique(cache_set->begin(),cache_set->end());
        cache_set->erase(last_it,cache_set->end());

	return 1;
    }
    int ActiveVisitor::post_visit(const refCond &cond) {
        unsigned int i;

        auto cache_set = &cache_cond.insert(
                std::make_pair(cond,std::vector<uint64_t>())).first->second;
        for(i = 0; i < cond->expr_count; i++) {
            auto it = cache_expr.find(cond->expr[i]);

            assert(it != cache_expr.end());

            cache_set->insert(
                    cache_set->end(),
                    it->second.begin(),
                    it->second.end());
        }
        for(i = 0; i < cond->cond_count; i++) {
            auto it = cache_cond.find(cond->cond[i]);

            assert(it != cache_cond.end());

            cache_set->insert(
                    cache_set->end(),
                    it->second.begin(),
                    it->second.end());
        }

        std::sort(cache_set->begin(),cache_set->end());
        auto last_it = std::unique(cache_set->begin(),cache_set->end());
        cache_set->erase(last_it,cache_set->end());
        
	return 1;
    }

    bool ActiveSolver::solve(
	    const std::unordered_set<refCond> &target_constr,
	    const std::unordered_set<refCond> &constr,
	    std::unordered_map<refExpr,uint64_t> *concrete
    ) {
	std::unordered_set<refCond> act_constr;
        /*std::vector<uint64_t> in_addr;
        std::unordered_set<uint64_t> in_addrset;

        act_vis.iter_walk(target_constr.begin(),target_constr.end());
        for(auto it = target_constr.begin(); it != target_constr.end(); it++) {
            act_vis.walk(*it);

            const auto &tmpvec = act_vis.get_cond_addr(*it);
            in_addr.insert(in_addr.end(),tmpvec.begin(),tmpvec.end());
        }
        std::sort(in_addr.begin(),in_addr.end());
        auto last_it = std::unique(in_addr.begin(),in_addr.end());
        in_addr.erase(last_it,in_addr.end());

        in_addrset.insert(in_addr.begin(),in_addr.end());

	act_constr = target_constr;
        act_constr.insert(constr.begin(),constr.end());
        
        //Try to use previous symbol value
        for(auto it = in_addrset.begin(); it != in_addrset.end(); it++) {
            if(*it < 0x2000) {
                err("  *%08lx\n",*it);
            }
        }*/
        /*for(
            auto sym_it = mem_symbol_concrete.begin();
            sym_it != mem_symbol_concrete.end();
            sym_it++
        ) {
            info("  %08lx\n",sym_it->first);
            if(in_addrset.find(sym_it->first) == in_addrset.end()) {
                act_constr.insert(sym_it->second);
            } else {
                err("conflict\n");
            }
        }*/

	/*for(auto cond_it = constr.begin(); cond_it != constr.end(); cond_it++) {
            act_vis.walk(*cond_it);

            const auto &out_addr = act_vis.get_cond_addr(*cond_it);

            auto in_it = in_addr.begin();
            auto out_it = out_addr.begin();
            while(in_it != in_addr.end() && out_it != out_addr.end()) {
                if(*in_it == *out_it) {
		    act_constr.insert(*cond_it);
		    break;
                }
                if(*in_it < *out_it) {
                    in_it++;
                } else {
                    out_it++;
                }
            }
	}*/

        act_constr = constr;
        act_constr.insert(target_constr.begin(),target_constr.end());
	dbg("%u %u\n",concrete->size(),act_constr.size());

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

	//get memory record
	const auto &tmp_selset = build_vis->get_mem_record();
	//copy old select record
        next_selset = cstate->select_set;
	//handle solid select address
	for(auto it = tmp_selset.begin(); it != tmp_selset.end(); it++) {
	    if((*it)->idx->type == ExprImm) {
		auto addr = std::static_pointer_cast<const BytVec>(
                        (*it)->idx)->data;
		cas->handle_select(addr,(*it)->size);
	    } else {
                next_selset.insert(*it);
            }
	}

	//initialize constraint
	constr.insert(jmp_cond);
	constr.insert(cstate->constr.begin(),cstate->constr.end());
        constr.insert(cas->mem_constr.begin(),cas->mem_constr.end());
	target_constr.insert(jmp_cond);

	//initialize solver variable
	//TODO support instruction mode

	concrete[next_exrpc] = 0;
	for(
	    auto it = cas->mem_symbol.begin();
	    it != cas->mem_symbol.end();
	    it++
	) {
	    concrete[it->second] = 0;
	}
	for(auto it = next_selset.begin(); it != next_selset.end(); it++) {
	    concrete[(*it)->idx] = 0;
	}

	while(true) {
	    //solve
	    if(!act_solver->solve(
                        target_constr,
                        constr,
                        &concrete)) {
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
		for(
		    auto it = cas->mem_symbol.begin();
		    it != cas->mem_symbol.end();
		    it++
		) {
		    concrete[it->second] = 0;
		}
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

            /*for(
	        auto it = cas->mem_symbol.begin();
		it != cas->mem_symbol.end();
		it++
	    ) {
                assert(it->second->size == 8);
		nstate->mem_symbol_concrete[it->first] = cond_eq(
                        it->second,
                        BytVec::create_imm(
                            it->second->size,
                            concrete[it->second]));
	    }*/

	    statelist.push_back(nstate);
	    target_constr.insert(cond_not(cond_pc));

	    auto rawpc = nstate->pc.rawpc;

	    nstate->path = cstate->path;
	    nstate->path.push_back(rawpc);
	    nstate->blkmap = cstate->blkmap;

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
	    if(nstate->path.size() >= 1000) {
		for(
		    auto it = cas->mem_symbol.begin();
		    it != cas->mem_symbol.end();
		    it++
		) {
		    concrete[it->second] = 0;
		}
		ctx->solver->solve(constr,&concrete);

                std::map<uint64_t,uint64_t> tmpmap;
		for(
		    auto it = cas->mem_symbol.begin();
		    it != cas->mem_symbol.end();
		    it++
		) {
                    bool ret = tmpmap.insert(std::make_pair(it->first,concrete[it->second])).second;
                    if(ret == false) {
                        err("duplicate symbol %08lx\n",it->first);
                    }
		}
                for(auto it = tmpmap.begin(); it != tmpmap.end(); it++) {
		    dbg("sym %08lx %x\n",it->first,it->second);
                }

		dbg("long path %d\n",count);
		exit(0);
	    }
	}

	return statelist;
    }

    int Executor::execute(uint64_t target_rawpc) {
	refSnapshot snap;
	std::unordered_map<ProgCtr,std::vector<refBlock> > block_cache;
	refState nstate,cstate;
	std::vector<refBlock> blklist;
	refBlock cblk;

        FILE *f = fopen("pathlog","w");
	
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

        //Init ActiveSolver
	act_solver = new ActiveSolver(ctx->solver);

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
	    dbg("length %u state %u maxlen %u queue %u\n",cstate->length,count,maxlen,worklist.size());

            //work_dispatch();

	    auto blklist_it = block_cache.find(cstate->pc);
	    if(blklist_it == block_cache.end()) {
		blklist = snap->translate_bb(cstate->pc);
		block_cache[cstate->pc] = blklist;
	    } else {
		blklist = blklist_it->second;
	    }

            if(blklist.size() == 0) {
                unsigned int j;
                fprintf(f,"\n");
		for(j = 0; j < cstate->path.size(); j++) {
		    fprintf(f,"%08lx\n",cstate->path[j]);
		}
                fflush(f);
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
	}

        delete act_solver;

	ctx->destroy_vm(vm);
	return 0;
    }
};
