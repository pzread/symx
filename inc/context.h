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

    class Context {
	private:
	    int last_varid;

	public:
	    virtual ~Context() {};
	    virtual VirtualMachine* create_vm() = 0;
	    virtual int destroy_vm(VirtualMachine *vm) = 0;
	    
	    int get_next_varid() {
		last_varid += 1;
		return last_varid;
	    }
    };
}

#endif
