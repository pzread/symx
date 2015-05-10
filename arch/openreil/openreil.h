
#include"vm.h"
#include"context.h"

#ifndef _OPENREIL_H_
#define _OPENREIL_H_

namespace openreil {
    class VirtualMachine : public symx::VirtualMachine {
	public:
	    uint64_t event_get_pc();
	    int suspend();
    };
    class Context : public symx::Context {
	private:
	    const char *container_path;
	    const char *exe_path;

	public:
	    Context(const char *_exe_path) :
		symx::Context(256,64),
		container_path("."),
		exe_path(_exe_path) {}
	    VirtualMachine* create_vm();
	    int destroy_vm(symx::VirtualMachine *vm);
    };
}

#endif
