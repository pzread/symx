#define LOG_PREFIX "main"

#include<stdio.h>
#include<stdlib.h>

#include"utils.h"
#include"state.h"
#include"solver/z3.h"
#include"arch/openreil/openreil.h"

using namespace symx;

int main() {
    
    //Just for test
    /*vm::VirtualMachine *vm = new vm::VirtualMachine();
    const char *argv[] = {"sample",NULL};

    vm->create(".","./sample",argv);

        vm->destroy();

    delete vm;*/

    Solver *solver = new z3_solver::Z3Solver();
    Context *context = new openreil::Context(solver,"./sample");
    state_executor(context);
    delete context;
    return 0;
}
