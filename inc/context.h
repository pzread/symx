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
	public:
	    const unsigned int NUMREG;
	    const unsigned int NUMFLAG;

	    virtual ~Context() {};
	    virtual VirtualMachine* create_vm() = 0;
	    virtual int destroy_vm(VirtualMachine *vm) = 0;

	    Context(const unsigned int _NUMREG,const unsigned int _NUMFLAG)
		: NUMREG(_NUMREG),NUMFLAG(_NUMFLAG) {}
    };
}

#endif
