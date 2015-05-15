#include<libopenreil.h>
#include"vm.h"
#include"context.h"

#ifndef _OPENREIL_H_
#define _OPENREIL_H_

namespace openreil {
    using namespace openreil;

    class VirtualMachine;

    class Snapshot : public symx::Snapshot {
	private:
	    VirtualMachine *const vm;

	    static int inst_handler(reil_inst_t *inst,void *ctx);
	    int translate(
		    uint8_t *code,
		    const symx::ProgCtr &pc,
		    size_t len) const;

	public:
	    Snapshot(VirtualMachine *vm,const uint64_t *_reg,const bool *_flag);
	    int mem_read(uint8_t *buf,uint64_t pos,size_t len) const;
    };
    class VirtualMachine : public symx::VirtualMachine {
	public:
	    uint64_t event_get_pc() const;
	    symx::refSnapshot event_suspend();
	    int mem_read(uint8_t *buf,uint64_t pos,size_t len);
    };
    class Context : public symx::Context {
	private:
	    const char *container_path;
	    const char *exe_path;

	public:
	    Context(const char *_exe_path);
	    VirtualMachine* create_vm();
	    int destroy_vm(symx::VirtualMachine *vm);
    };
}

#endif
