#include<stdint.h>
#include<unistd.h>

#ifndef _VM_H_
#define _VM_H_

namespace vm {
    class VirtualMachine {
	public:
	    int Create(
		    const char *container_path,
		    const char *exe_path,
		    const char **argv);
	    int Continue(uint64_t pc);
    };
}

#endif
