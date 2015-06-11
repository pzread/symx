#ifndef _CONTEXT_H_
#define _CONTEXT_H_

#include<stdint.h>
#include<memory>
#include<queue>
#include<vector>
#include<unordered_map>
#include<unordered_set>

#include"utils.h"
#include"vm.h"

namespace symx {
    using namespace symx;

    class Solver {
	public:
            virtual ~Solver() {};
	    virtual bool solve(
		    const std::unordered_set<refCond> &cons,
		    std::unordered_map<refExpr,uint64_t> *var) = 0;
    };
    class Context {
	private:
	    int last_varid = 0;

	public:
	    Solver *solver;

	    virtual ~Context() {};
	    virtual VirtualMachine* create_vm() = 0;
	    virtual int destroy_vm(VirtualMachine *vm) = 0;

	    Context(Solver *_solver) : solver(_solver) {}
	    int get_next_varid() {
		last_varid += 1;
		return last_varid;
	    }
    };
}

#endif
