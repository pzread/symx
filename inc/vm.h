#ifndef _VM_H_
#define _VM_H_

#include<stdint.h>
#include<unistd.h>
#include<limits.h>
#include<capstone/capstone.h>
#include<vector>
#include<memory>
#include<bitset>
#include<map>
#include<unordered_map>
#include<mutex>

#include"utils.h"
#include"expr.h"
#include"state.h"
#include"context.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE		0x1000
#endif
#define PAGE_MASK		(~0xFFF)

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

    REGIDX_GS,
    REGIDX_GS_BASE,

    REGIDX_EFLAGS,
    REGIDX_DFLAG,

    REGIDX_CF,
    REGIDX_PF,
    REGIDX_AF,
    REGIDX_ZF,
    REGIDX_SF,
    REGIDX_OF,

    REGIDX_END
};
#pragma pack(push)
#pragma pack(4)
struct vmcom_enter {
    uint32_t entrypc;
    uint32_t endpc;
};
struct vmcom_context {
    uint32_t pc;
    uint32_t reg[REGIDX_END];
    uint32_t flag;
};
struct vmcom_membuf {
    uint8_t buf[16384];
    uint32_t pos;
    uint32_t len;
};
struct vmcom_frame {
    uint32_t evt;
    union {
	struct vmcom_enter enter;
	struct vmcom_context context;    
	struct vmcom_membuf membuf;
    };
};
#pragma pack(pop)

namespace symx {
    using namespace symx;

    class Snapshot {
	private:
	    csh cs;

	public:
	    virtual int mem_read(
		    uint8_t *buf,
		    uint64_t pos,
		    size_t len) const = 0;
	    virtual std::vector<refBlock> translate(
		    uint8_t *code,
		    const ProgCtr &pc,
		    size_t len) const = 0;

	    Snapshot(cs_arch arch,cs_mode mode);
	    std::vector<refBlock> translate_bb(const symx::ProgCtr &pc) const;

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
	    virtual uint64_t event_get_pc() const = 0;
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

    class MemPage : public std::enable_shared_from_this<MemPage> {
	public:
	    const uint64_t start;
	    const unsigned int prot;
	    std::bitset<PAGE_SIZE> dirty;
	    std::bitset<PAGE_SIZE> symbol;
	    MemPage(const uint64_t _start,const unsigned int _prot)
		: start(_start),prot(_prot) {}
    };
    class AddrSpace : public std::enable_shared_from_this<AddrSpace>{
	private:
	    Context *ctx;
	    const refSnapshot snap;
	    std::map<uint64_t,MemPage> page_map;

	public:
            std::mutex access_lock;
	    refExpr mem;
	    std::unordered_map<uint64_t,refBytVec> mem_symbol;
	    std::unordered_set<refCond> mem_constr;

	    AddrSpace(Context *_ctx,const refSnapshot &_snap);
	    int read(refState state,uint8_t *buf,uint64_t pos,size_t len);
	    int handle_select(const uint64_t idx,const unsigned int size);
    };
    class MemRecord : public std::enable_shared_from_this<MemRecord> {
	public:
	    const refOperator oper;
	    const refExpr mem;
	    const refExpr idx;
	    const unsigned int size;
	    MemRecord(
		    const refOperator &_oper,
		    const refExpr &_mem,
		    const refExpr &_idx,
		    const unsigned int _size)
		: oper(_oper),mem(_mem),idx(_idx),size(_size) {}
    };
}

#endif
