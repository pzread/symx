#include<vector>
#include<string>
#include<unordered_map>
#include<libopenreil.h>

#include"utils.h"
#include"context.h"
#include"vm.h"

#ifndef _OPENREIL_H_
#define _OPENREIL_H_

namespace openreil {
    using namespace openreil;

    class VirtualMachine;

    class Snapshot : public symx::Snapshot {
	private:
	    VirtualMachine *const vm;

	    static int inst_handler(reil_inst_t *inst,void *ctx);
	    symx::refExpr translate_get_arg(
		    const std::unordered_map<std::string,symx::refExpr> &regmap,
		    const reil_arg_t &arg) const;
	    int translate_set_arg(
		    std::unordered_map<std::string,symx::refExpr> *regmap,
		    const reil_arg_t &arg,
		    const symx::refExpr &value) const;
	    symx::refBlock translate(
		    uint8_t *code,
		    const symx::ProgCtr &pc,
		    size_t len) const;

	public:
	    Snapshot(VirtualMachine *vm,const uint64_t *_reg);
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
	    Context(symx::Solver *_solver,const char *_exe_path)
		: symx::Context(_solver),
		container_path("."),
		exe_path(_exe_path) {}
	    VirtualMachine* create_vm();
	    int destroy_vm(symx::VirtualMachine *vm);
    };
}

#endif
