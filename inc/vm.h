#include<stdint.h>
#include<unistd.h>
#include<limits.h>
#include<vector>
#include<memory>

#include"expr.h"
#include"utils.h"

#ifndef _VM_H_
#define _VM_H_

#define UNIX_PATH_MAX		108
#define VMCOM_EVT_ENTER		1
#define VMCOM_EVT_EXECUTE	2
#define VMCOM_EVT_RET		10
#define VMCOM_EVT_READMEM	11

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
    REGIDX_END
};
enum FLAGIDX {
    FLAGIDX_CF = 0,
    FLAGIDX_PF,
    FLAGIDX_AF,
    FLAGIDX_ZF,
    FLAGIDX_SF,
    FLAGIDX_OF,
    FLAGIDX_END
};
#pragma pack(push)
#pragma pack(4)
struct vmcom_context {
    uint32_t pc;
    uint32_t reg[REGIDX_END];
    uint32_t flag;
};
struct vmcom_membuf {
    uint8_t buf[4096];
    uint32_t pos;
    uint32_t len;
};
struct vmcom_frame {
    int evt;
    union {
	struct vmcom_context context;    
	struct vmcom_membuf membuf;
    };
};
#pragma pack(pop)

namespace symx {
    using namespace symx;

    class Snapshot;
    typedef std::shared_ptr<Snapshot> refSnapshot;

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

    class Snapshot {
	public:
	    virtual int mem_read(uint8_t *buf,uint64_t pos,size_t len) = 0;

	    std::vector<refExpr> reg;
	    std::vector<refCond> flag;
    };
    class VirtualMachine {
	private:
	    void *data;

	    int vmcom_create();
	    int vmcom_accept(int listen_fd);

	protected:
	    enum VMSTATE {
		RUNNING,
		EVENT,
		SUSPEND
	    } state;
	    char name[NAME_MAX + 1];
	    pid_t pid;
	    int com_evt;
	    struct vmcom_frame *com_mem;
	    
	    int set_state(VMSTATE next_state);

	public:
	    virtual ~VirtualMachine() {};
	    virtual uint64_t event_get_pc() = 0;
	    virtual refSnapshot event_suspend() = 0;

	    int create(
		    const char *container_path,
		    const char *exe_path,
		    const char **argv);
	    int destroy();
	    int event_wait();
	    int event_send(int evt);
	    int event_ret();
    };
}

#endif
