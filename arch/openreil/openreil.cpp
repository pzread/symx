#define LOG_PREFIX "openreil"

#include<stdint.h>
#include<assert.h>
#include<libopenreil.h>

#include"utils.h"
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
int VirtualMachine::suspend() {
    int ret;

    if((ret = symx::VirtualMachine::suspend())) {
	return ret;
    }

    return 0;
}
