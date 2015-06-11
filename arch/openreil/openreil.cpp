#define LOG_PREFIX "openreil"

#include<stdlib.h>
#include<string.h>
#include<stdint.h>
#include<assert.h>
#include<string>
#include<vector>
#include<unordered_map>
#include<libopenreil.h>

#include"utils.h"
#include"expr.h"
#include"vm.h"
#include"state.h"
#include"arch/openreil/openreil.h"

using namespace openreil;

static std::vector<reil_inst_t> instlist;
static const char *REGNAME[] = {
    "R_EAX",
    "R_EBX",
    "R_ECX",
    "R_EDX",
    "R_EDI",
    "R_ESI",
    "R_EBP",
    "R_ESP",

    "R_GS",
    "R_GS_BASE",

    "R_EFLAGS",
    "R_DFLAG",

    "R_CF",
    "R_PF",
    "R_AF",
    "R_ZF",
    "R_SF",
    "R_OF",
};
static const unsigned int REGSIZE[] = {
    32,
    32,
    32,
    32,
    32,
    32,
    32,
    32,
    16,
    32,
    32,
    32,
    1,
    1,
    1,
    1,
    1,
    1,
};
static const unsigned int REILSIZE[] = {
    1,
    8,
    16,
    32,
    64,
};
static const symx::refExpr IMMFALSE = symx::BytVec::create_imm(1,0x0);
static const symx::refExpr IMMTRUE = symx::BytVec::create_imm(1,0x1);

VirtualMachine* Context::create_vm() {
    VirtualMachine *vm = new VirtualMachine();
    const char *argv[] = {exe_path,NULL};
    if(vm->create(container_path,exe_path,argv)) {
	err("virtual machine create failed\n");
    }
    return vm;
}
int Context::destroy_vm(symx::VirtualMachine *vm) {
    vm->destroy();
    delete vm;
    return 0;
}
uint64_t VirtualMachine::event_get_pc() const {
    assert(com_mem->evt == VMCOM_EVT_EXECUTE);
    return com_mem->context.pc;
}
symx::refSnapshot VirtualMachine::event_suspend() {
    int i;
    uint64_t reg[REGIDX_END];

    if(set_state(SUSPEND)) {
	return nullptr;
    }

    for(i = 0; i < REGIDX_EFLAGS; i++) {
	reg[i] = com_mem->context.reg[i];
    }

    reg[REGIDX_EFLAGS] = com_mem->context.flag;
    reg[REGIDX_DFLAG] = (com_mem->context.flag >> 10) & 0x1;

    reg[REGIDX_CF] = (com_mem->context.flag >> 0) & 0x1;
    reg[REGIDX_PF] = (com_mem->context.flag >> 2) & 0x1;
    reg[REGIDX_AF] = (com_mem->context.flag >> 4) & 0x1;
    reg[REGIDX_ZF] = (com_mem->context.flag >> 6) & 0x1;
    reg[REGIDX_SF] = (com_mem->context.flag >> 7) & 0x1;
    reg[REGIDX_OF] = (com_mem->context.flag >> 11) & 0x1;

    return ref<Snapshot>(this,reg);
}
int VirtualMachine::mem_read(uint8_t *buf,uint64_t pos,size_t len) {

    access_lock.lock();

    assert(len < sizeof(com_mem->membuf.buf));

    com_mem->membuf.pos = (uint32_t)pos;
    com_mem->membuf.len = len;
    event_send(VMCOM_EVT_READMEM);   
    event_wait();

    if(com_mem->membuf.len == 0) {
	return -1;
    }

    memcpy(buf,com_mem->membuf.buf,len);

    access_lock.unlock();

    return 0;
}

Snapshot::Snapshot(VirtualMachine *_vm,const uint64_t *_reg)
    : symx::Snapshot(CS_ARCH_X86,CS_MODE_32),vm(_vm)
{
    int i;
    for(i = 0; i < REGIDX_END; i++) {
	reg.push_back(symx::BytVec::create_imm(REGSIZE[i],_reg[i]));
    }
}
int Snapshot::mem_read(uint8_t *buf,uint64_t pos,size_t len) const {
    return  vm->mem_read(buf,pos,len);
}

#define MAX_ARG_STR 50
const char *inst_op[] = {
    "NONE", "UNK", "JCC",
    "STR", "STM", "LDM",
    "ADD", "SUB", "NEG", "MUL", "DIV", "MOD", "SMUL", "SDIV", "SMOD",
    "SHL", "SHR", "AND", "OR", "XOR", "NOT",
    "EQ", "LT"
};
int arg_size[] = { 1, 8, 16, 32, 64 };
char *arg_print(reil_arg_t *arg,char *arg_str) {
    memset(arg_str, 0, MAX_ARG_STR);
    switch (arg->type) {
    case A_NONE:
        break;
    case A_REG:
    case A_TEMP:
        snprintf(
		arg_str,
		MAX_ARG_STR - 1,
		"%s:%d",
		arg->name,
		arg_size[arg->size]);
        break;
    case A_CONST:
        snprintf(
		arg_str,
		MAX_ARG_STR - 1,
		"%llx:%d",
		arg->val,
		arg_size[arg->size]);
        break;
    }
    return arg_str;
}
void inst_print(const std::vector<reil_inst_t>::iterator &inst) {
    char arg_str[3][MAX_ARG_STR];
    arg_print(&inst->a, arg_str[0]);
    arg_print(&inst->b, arg_str[1]);
    arg_print(&inst->c, arg_str[2]);
    dbg("%.8llx.%.2x %7s %16s, %16s, %16s\n",
	    inst->raw_info.addr,
	    inst->inum,
	    inst_op[inst->op],
	    arg_str[0],
	    arg_str[1],
	    arg_str[2]);
}
int Snapshot::inst_handler(reil_inst_t *inst,void *ctx) {
    instlist.push_back(*inst);
    return 0;
}
std::vector<symx::refBlock> Snapshot::translate(
	uint8_t *code,
	const symx::ProgCtr &pc,
	size_t len
) const {
    unsigned int i;
    uint64_t rawpc = pc.rawpc;
    reil_t reil;
    int translated;

    std::vector<symx::refBlock> blklist;
    symx::refCond prevcond = nullptr;
    symx::refExpr mem;
    std::vector<symx::refExpr> reglist;
    std::vector<symx::refCond> flaglist;
    std::unordered_map<std::string,symx::refExpr> regmap;
    symx::refExpr xra,xrb,xrc;
    
    //initialize openreil, translate to reil IR
    reil = reil_init(ARCH_X86,inst_handler,(void*)&translated);
    instlist.clear();
    reil_translate(reil,rawpc,code,len);
    reil_close(reil);

    //initialize dangle memory, register
    mem = symx::BytMem::create_dangle(-1);
    for(i = 0; i < REGIDX_END; i++) {
	auto reg = symx::BytVec::create_dangle(REGSIZE[i],i);
	regmap[REGNAME[i]] = reg;
    }

    blklist.clear();

    for(auto ins = instlist.begin(); ins != instlist.end(); ins++) {
	inst_print(ins);

	switch(ins->op) {
	    case I_STR:
		translate_set_arg(
			&regmap,
			ins->c,
			translate_get_arg(regmap,ins->a));
		break;

	    case I_ADD:
	    case I_SUB:
	    case I_MUL:
	    case I_SHR:
	    case I_SHL:
		xra = translate_fixsize(
			translate_get_arg(regmap,ins->a),
			ins->a.size);
		xrb = translate_fixsize(
			translate_get_arg(regmap,ins->b),
			ins->b.size);

		switch(ins->op) {
		    case I_ADD:
			xrc = symx::expr_add(xra,xrb);
			break;
		    case I_SUB:
			xrc = symx::expr_sub(xra,xrb);
			break;
		    case I_MUL:
			xrc = symx::expr_mul(xra,xrb);
			break;
		    case I_SHR:
			xrc = symx::expr_lshr(xra,xrb);
			break;
		    case I_SHL:
			xrc = symx::expr_shl(xra,xrb);
			break;
		    default:
			err("unexpected\n");
			break;
		}
		translate_set_arg(&regmap,ins->c,xrc);
		break;

	    case I_AND:
	    case I_OR:
	    case I_XOR:
		xra = translate_get_arg(regmap,ins->a);
		xrb = translate_get_arg(regmap,ins->b);

		if(xra->size != xrb->size) {
		    xra = translate_fixsize(xra,ins->c.size);
		    xrb = translate_fixsize(xrb,ins->c.size);
		}

		switch(ins->op) {
		    case I_AND:
			xrc = symx::expr_and(xra,xrb);
			break;
		    case I_OR:
			xrc = symx::expr_or(xra,xrb);
			break;
		    case I_XOR:
			xrc = symx::expr_xor(xra,xrb);
			break;
		    
		    default:
			err("unexpected\n");
			break;
		}
		translate_set_arg(&regmap,ins->c,xrc);
		break;

	    case I_NEG:
	    case I_NOT:
		xra = translate_get_arg(regmap,ins->a);
		switch(ins->op) {
		    case I_NEG:
			xrc = symx::expr_neg(xra);
			break;
		    case I_NOT:
			xrc = symx::expr_not(xra);
			break;
		    default:
			err("unexpected\n");
			break;
		}
		translate_set_arg(&regmap,ins->c,xrc);
		break;

	    case I_EQ:
	    case I_LT:
		xra = translate_fixsize(
			translate_get_arg(regmap,ins->a),
			ins->a.size);
		xrb = translate_fixsize(
			translate_get_arg(regmap,ins->b),
			ins->b.size);

		switch(ins->op) {
		    case I_EQ:
			xrc = symx::expr_ite(
				symx::cond_eq(xra,xrb),
				IMMTRUE,
				IMMFALSE);
			break;
		    case I_LT:
			xrc = symx::expr_ite(
				symx::cond_ul(xra,xrb),
				IMMTRUE,
				IMMFALSE);
			break;
		    default:
			err("unexpected\n");
			break;
		}
		translate_set_arg(&regmap,ins->c,xrc);
		break;

	    case I_LDM:
		xra = translate_fixsize(
			translate_get_arg(regmap,ins->a),
			ins->a.size);
		translate_set_arg(
			&regmap,
			ins->c,
			symx::expr_select(mem,xra,REILSIZE[ins->c.size]));
		break;

	    case I_STM:
		xra = translate_fixsize(
			translate_get_arg(regmap,ins->a),
			ins->a.size);
		mem = symx::expr_store(
			mem,
			translate_get_arg(regmap,ins->c),
			xra);
		break;

	    case I_JCC:
	    {
		xra = translate_get_arg(regmap,ins->a);
		xrc = translate_get_arg(regmap,ins->c);

		reglist.clear();
		for(i = 0; i < REGIDX_END; i++) {
		    reglist.push_back(regmap[REGNAME[i]]);
		}

		auto cond = symx::cond_eq(
			xra,
			symx::BytVec::create_imm(xra->size,0));

		if(prevcond == nullptr) {
		    blklist.push_back(ref<symx::Block>(
				mem,
				reglist,
				flaglist,
				symx::cond_not(cond),
				xrc));
		    prevcond = cond;
		} else {
		    blklist.push_back(ref<symx::Block>(
				mem,
				reglist,
				flaglist,
				symx::cond_and(prevcond,symx::cond_not(cond)),
				xrc));
		    prevcond = symx::cond_and(prevcond,cond);
		}

		break;
	    }
	    case I_NONE:
		break;

	    default:
		err("unsupport unstruction %d\n",ins->op);
		break;
	}
    }

    instlist.clear();

    //assume openreil always has JCC jumping to next block
    //something like this at the end of the block
    //JCC	1:1	    ,	    0xDEADBEEF

    return blklist;
}
symx::refExpr Snapshot::translate_fixsize(
	symx::refExpr exr,
	unsigned int size
) const {
    if(exr->size < REILSIZE[size]) {
	return symx::expr_zext(exr,REILSIZE[size]);
    } else if(exr->size > REILSIZE[size]) {
	return symx::expr_extract(exr,0,REILSIZE[size]);
    }
    return exr;
}
symx::refExpr Snapshot::translate_get_arg(
	const std::unordered_map<std::string,symx::refExpr> &regmap,
	const reil_arg_t &arg) const {
    //unsigned int size = REILSIZE[arg.size];
    symx::refExpr xrt;

    assert(arg.type == A_REG || arg.type == A_TEMP || arg.type == A_CONST);

    if(arg.type == A_REG || arg.type == A_TEMP) {
	auto it = regmap.find(arg.name);

	assert(it != regmap.end());

	xrt = it->second;
	return xrt;
    } else {
	return symx::BytVec::create_imm(REILSIZE[arg.size],arg.val);
    }
}
int Snapshot::translate_set_arg(
	std::unordered_map<std::string,symx::refExpr> *regmap,
	const reil_arg_t &arg,
	const symx::refExpr &value) const {
    unsigned int size = REILSIZE[arg.size];
    symx::refExpr xrt;

    assert(arg.type == A_REG || arg.type == A_TEMP);
    
    if(size == value->size) {
	xrt = value;
    } else if(size < value->size) {
	xrt = symx::expr_extract(value,0,size);
    } else if(size > value->size) {
	xrt = symx::expr_zext(value,size);
    }

    auto ret = regmap->insert(std::make_pair(std::string(arg.name),xrt));
    if(!ret.second) {
	regmap->find(arg.name)->second = xrt;
    }
    return 0;
}

