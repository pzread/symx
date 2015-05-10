#define LOG_PREFIX "main"

#include<stdio.h>
#include<stdlib.h>

#include"utils.h"
#include"vm.h"
#include"arch/openreil/openreil.h"

using namespace symx;

int main() {
    
    //Just for test
    /*vm::VirtualMachine *vm = new vm::VirtualMachine();
    const char *argv[] = {"sample",NULL};

    vm->create(".","./sample",argv);

        vm->destroy();

    delete vm;*/

    Context *context = new openreil::Context("./sample");
    VirtualMachine *vm = context->create_vm();

    if(vm->event_wait() != VMCOM_EVT_ENTER) {
	err("unexpected event\n");
    }
    vm->event_ret();

    while(vm->event_wait() == VMCOM_EVT_EXECUTE) {
	if(vm->event_get_pc() == 0x080483FB) {
	    info("find main entry\n");
	    break;
	}
	vm->event_ret();
    }

    vm->suspend();

    context->destroy_vm(vm);
    delete context;
    return 0;
}
