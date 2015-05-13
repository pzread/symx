#define LOG_PREFIX "openreil"

#include<stdint.h>
#include<assert.h>
#include<libopenreil.h>

#include"utils.h"
#include"vm.h"
#include"expr.h"
#include"arch/openreil/openreil.h"

using namespace openreil;

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
uint64_t VirtualMachine::event_get_pc() {
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
    com_mem->membuf.pos = (uint32_t)pos;
    com_mem->membuf.len = len;
    event_send(VMCOM_EVT_READMEM);   
    event_wait();
    return 0;
}

Snapshot::Snapshot(
	VirtualMachine *_vm,
	const uint64_t *_reg,
	const bool *_flag
) : vm(_vm) {
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
int Snapshot::mem_read(uint8_t *buf,uint64_t pos,size_t len) {
    return vm->mem_read(buf,pos,len);
}
