#define LOG_PREFIX "openreil"

#include<stdlib.h>
#include<string.h>
#include<stdint.h>
#include<assert.h>
#include<libopenreil.h>

#include"utils.h"
#include"vm.h"
#include"expr.h"
#include"arch/openreil/openreil.h"

using namespace openreil;

Context::Context(const char *_exe_path)
    : symx::Context(256,64),container_path("."),exe_path(_exe_path)
{}

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
    bool flag[FLAGIDX_END];

    if(set_state(SUSPEND)) {
	return nullptr;
    }

    for(i = 0;i < REGIDX_END;i++) {
	reg[i] = com_mem->context.reg[i];
    }
    flag[FLAGIDX_CF] = (com_mem->context.flag >> 0) & 0x1;
    flag[FLAGIDX_PF] = (com_mem->context.flag >> 2) & 0x1;
    flag[FLAGIDX_AF] = (com_mem->context.flag >> 4) & 0x1;
    flag[FLAGIDX_ZF] = (com_mem->context.flag >> 6) & 0x1;
    flag[FLAGIDX_SF] = (com_mem->context.flag >> 7) & 0x1;
    flag[FLAGIDX_OF] = (com_mem->context.flag >> 11) & 0x1;

    return ref<Snapshot>(this,reg,flag);
}
int VirtualMachine::mem_read(uint8_t *buf,uint64_t pos,size_t len) {
    assert(len < sizeof(com_mem->membuf.buf));

    com_mem->membuf.pos = (uint32_t)pos;
    com_mem->membuf.len = len;
    event_send(VMCOM_EVT_READMEM);   
    event_wait();

    memcpy(buf,com_mem->membuf.buf,len);
    return 0;
}

Snapshot::Snapshot(VirtualMachine *_vm,const uint64_t *_reg,const bool *_flag)
    : symx::Snapshot(CS_ARCH_X86,CS_MODE_32),vm(_vm)
{
    int i;
    for(i = 0;i < REGIDX_END;i++) {
	reg.push_back(symx::BytVec::create_imm(32,_reg[i]));
    }
    for(i = 0;i < FLAGIDX_END;i++) {
	if(_flag[i]) {
	    flag.push_back(symx::Cond::create_true());
	} else {
	    flag.push_back(symx::Cond::create_false());
	}
    }
}
int Snapshot::mem_read(uint8_t *buf,uint64_t pos,size_t len) const {
    return vm->mem_read(buf,pos,len);
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
void inst_print(reil_inst_t *inst) {
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
    inst_print(inst);
    return 0;
}
int Snapshot::translate(
	uint8_t *code,
	const symx::ProgCtr &pc,
	size_t len
) const {
    uint64_t rawpc = pc.rawpc;
    reil_t reil;
    int translated;
    
    reil = reil_init(ARCH_X86,inst_handler,(void*)&translated);
    reil_translate(reil,rawpc,code,len);
    reil_close(reil);

    return 0;
}
