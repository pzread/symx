#define LOG_PREFIX "main"

#include<stdio.h>
#include<stdlib.h>
#include"utils.h"
#include"vm.h"

int main() {
    
    //Just for test
    vm::VirtualMachine *vm = new vm::VirtualMachine();
    const char *argv[] = {"sample",NULL};

    vm->create(".","./sample",argv);

    if(vm->event_wait() != VMCOM_EVT_ENTER) {
	err("unexpected event\n");
    }
    vm->event_ret();

    while(vm->event_wait() == VMCOM_EVT_EXECUTE) {
	//info("in block %08lx\n",v);
	vm->event_ret();
    }
    vm->destroy();

    delete vm;
    return 0;
}
