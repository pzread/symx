#define LOG_PREFIX "main"

#include<stdio.h>
#include<stdlib.h>

#include"utils.h"
#include"state.h"
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
    state_executor(context);
    delete context;
    return 0;
}
