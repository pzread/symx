#define LOG_PREFIX "main"

#include<stdio.h>
#include<stdlib.h>
#include"utils.h"
#include"vm.h"

int main() {
    
    //Just for test
    vm::VirtualMachine *vm = new vm::VirtualMachine();
    const char *argv[] = {"sample",NULL};

    vm->Create(".","./sample",argv);

    delete vm;
    return 0;
}
