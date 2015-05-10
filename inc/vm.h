#include<stdint.h>
#include<unistd.h>
#include<limits.h>

#ifndef _VM_H_
#define _VM_H_

#define UNIX_PATH_MAX		108
#define VMCOM_EVT_ENTER		1
#define VMCOM_EVT_EXECUTE	2
#define VMCOM_EVT_RET		10

namespace symx {
    using namespace symx;

    /*class AddrSpace {
	public:
	    std::unordered_map<uint64_t,refBytVec> mem_symbol;
	    std::unordered_set<refCond> mem_constraint;
	    AddrSpace(Context *ctx,const refProbe &_probe);
	    int handle_select(const uint64_t idx,const unsigned int size);
	    refExpr get_mem() const;
	    std::vector<refOperator> source_select(
		    const refOperator &sel,
		    const std::unordered_map<refExpr,uint64_t> &var) const;
	private:
	    const refProbe probe;
	    Context *ctx;
	    refExpr mem;
	    std::map<uint64_t,MemPage> page_map;
    };*/

    //For X86_32
    enum REGIDX {
	REGIDX_EAX = 0,
	REGIDX_EBX,
	REGIDX_ECX,
	REGIDX_EDX,
	REGIDX_EDI,
	REGIDX_ESI,
	REGIDX_EBP,
	REGIDX_ESP,
    };
    #pragma pack(push)
    #pragma pack(4)
    struct vmcom_context {
	uint32_t pc;
	uint32_t reg[8];
	uint32_t flag;
    };
    struct vmcom_frame {
	int evt;
	union {
	    struct vmcom_context context;    
	};
    };
    #pragma pack(pop)

    class VirtualMachine {
	private:
	    enum {
		RUNNING,
		EVENT,
		SUSPEND
	    } state;
	    void *data;

	    int vmcom_create();
	    int vmcom_accept(int listen_fd);

	protected:
	    char name[NAME_MAX + 1];
	    pid_t pid;
	    int com_evt;
	    struct vmcom_frame *com_mem;

	public:
	    virtual ~VirtualMachine() {};
	    virtual uint64_t event_get_pc() = 0;

	    int create(
		    const char *container_path,
		    const char *exe_path,
		    const char **argv);
	    int destroy();
	    int event_wait();
	    int event_ret();
	    int suspend();
    };
}

#endif
