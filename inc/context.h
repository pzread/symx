#include<stdint.h>
#include<memory>
#include<queue>
#include<vector>
#include<unordered_map>
#include<unordered_set>

#include"vm.h"

#ifndef _CONTEXT_H_
#define _CONTEXT_H_

#define PAGE_SIZE 0x1000

namespace symx {
    class ProgCtr {
	public:
	    uint64_t rawpc;
	    int insmd;
	    ProgCtr() {}
	    ProgCtr(const uint64_t _rawpc,const int _insmd)
		: rawpc(_rawpc),insmd(_insmd) {}
	    bool operator==(const ProgCtr &other) const {
		return rawpc == other.rawpc && \
			      insmd == other.insmd;
	    }
    };
}

namespace std {
    template<> struct hash<symx::ProgCtr> {
	std::size_t operator()(const symx::ProgCtr &key) const {
	    return (key.rawpc << 8) | key.insmd; 
	}
    };
}

namespace symx {
    using namespace symx;

    class Context {
	public:
	    const unsigned int NUMREG;
	    const unsigned int NUMFLAG;

	    virtual ~Context() {};
	    virtual VirtualMachine* create_vm() = 0;
	    virtual int destroy_vm(VirtualMachine *vm) = 0;

	    Context(const unsigned int _NUMREG,const unsigned int _NUMFLAG) :
		NUMREG(_NUMREG),
		NUMFLAG(_NUMFLAG) {}
    };
}

#endif
