#define LOG_PREFIX "vm"

#include<stdlib.h>
#include<string.h>
#include<stdint.h>
#include<stddef.h>
#include<assert.h>
#include<unistd.h>
#include<limits.h>
#include<fcntl.h>
#include<sys/mman.h>
#include<sys/socket.h>
#include<sys/un.h>
#include<map>
#include<unordered_map>
#include<capstone/capstone.h>

#define LINUX
#define X86_32
extern "C" {
    #include<dr_api.h>
    #include<dr_inject.h>
    #include<dr_config.h>
}

#include"utils.h"
#include"vm.h"

using namespace symx;

int VirtualMachine::create(
	const char *container_path,
	const char *exe_path,
	const char **argv
) {
    void *data;
    process_id_t pid;
    int listen_fd;

    dr_inject_process_create(exe_path,argv,&data);
    pid = dr_inject_get_process_id(data);
    snprintf(name,sizeof(name),"symx_vm");

    if(dr_register_process(
	    exe_path,
	    pid,
	    false,
	    "../dynamorio",
	    DR_MODE_CODE_MANIPULATION,
	    false,
	    DR_PLATFORM_32BIT,
	    "")) {
	goto error;
    }
    if(dr_register_client(
	    exe_path,
	    pid,
	    false,
	    DR_PLATFORM_32BIT,
	    0,
	    0,
	    "./libvmclient.so",
	    name)) {
	goto error;
    }
    if(!dr_inject_process_inject(data,false,NULL)) {
	goto error;
    }

    listen_fd = vmcom_create();
    if(!dr_inject_process_run(data)) {
	goto error;
    }
    vmcom_accept(listen_fd);

    //dr_inject_wait_for_child(data,0);
    
    this->pid = pid;
    this->data = data;
    state = RUNNING;
    info("VM create: %d %s %s\n",this->pid,container_path,exe_path);
    return 0;

error:

    dr_inject_process_exit(data,true);
    return -1;
}
int VirtualMachine::vmcom_create() {
    char event_path[PATH_MAX + 1];
    char mem_path[PATH_MAX + 1];
    int mem_fd;
    int listen_fd;
    struct sockaddr_un addr;
    socklen_t addrlen;

    snprintf(mem_path,sizeof(mem_path),"%s_mem",name);
    unlink(mem_path);
    mem_fd = open(mem_path,O_RDWR | O_CREAT | O_TRUNC,0600);
    ftruncate(mem_fd,65536);
    com_mem = (struct vmcom_frame*)mmap(
	    NULL,
	    sizeof(vmcom_frame),
	    PROT_READ | PROT_WRITE,
	    MAP_SHARED,
	    mem_fd,
	    0);
    close(mem_fd);
    
    snprintf(event_path,sizeof(event_path),"%s_event",name);
    listen_fd = socket(AF_UNIX,SOCK_STREAM,0);
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path,event_path,UNIX_PATH_MAX - 1);
    unlink(addr.sun_path);
    addrlen = offsetof(struct sockaddr_un,sun_path) + strlen(addr.sun_path);
    bind(listen_fd,(struct sockaddr*)&addr,addrlen);
    listen(listen_fd,1024);

    return listen_fd;
}
int VirtualMachine::vmcom_accept(int listen_fd) {
    struct sockaddr_un addr;
    socklen_t addrlen;

    addrlen = sizeof(addr);
    com_evt = accept(listen_fd,(struct sockaddr*)&addr,&addrlen);
    close(listen_fd);
    return 0;
}
int VirtualMachine::destroy() {
    munmap(com_mem,sizeof(vmcom_frame));
    close(com_evt);
    dr_inject_process_exit(data,true);
    return 0;
}
int VirtualMachine::set_state(VMSTATE next_state) {
    if(next_state == EVENT) {
	assert(state = RUNNING);
    }
    if(next_state == RUNNING) {
	assert(state == EVENT);
    }
    if(next_state == SUSPEND) {
	assert(state == EVENT);
    }
    state = next_state;
    return 0;
}
int VirtualMachine::event_wait() {
    int evt;

    if(read(com_evt,&evt,sizeof(evt)) == sizeof(evt)) {
	state = EVENT;
	return evt;
    }
    return -1;
}
int VirtualMachine::event_send(int evt) {
    return write(com_evt,&evt,sizeof(evt));
}
int VirtualMachine::event_ret() {
    int evt = VMCOM_EVT_RET;

    if(set_state(RUNNING)) {
	return -1;
    }
    return write(com_evt,&evt,sizeof(evt));
}

Snapshot::Snapshot(cs_arch arch,cs_mode mode) {
    cs_open(arch,mode,&cs);
    cs_option(cs,CS_OPT_DETAIL,CS_OPT_ON);
}
refBlock Snapshot::translate_bb(const symx::ProgCtr &pc) const {
    refBlock ret;
    uint64_t curpc = pc.rawpc;
    uint64_t endpc = curpc;
    uint8_t code[8192];
    const uint8_t *codeptr;
    cs_insn *ins;
    size_t remain;
    uint8_t *block;

    cs_option(cs,CS_OPT_MODE,pc.mode);
    ins = cs_malloc(cs);
    remain = PAGE_SIZE - (curpc & (~PAGE_MASK));
    while(true) {
	if(mem_read(code,curpc,remain)) {
	    return nullptr;
	}
	codeptr = code;
	while(remain > 0) {
	    if(!cs_disasm_iter(cs,&codeptr,&remain,&curpc,ins)) {
		break;
	    }
	    dbg("%s %s\n",ins->mnemonic,ins->op_str);
	    if(cs_insn_group(cs,ins,CS_GRP_CALL) ||
		    cs_insn_group(cs,ins,CS_GRP_RET) ||
		    cs_insn_group(cs,ins,CS_GRP_IRET) ||
		    cs_insn_group(cs,ins,CS_GRP_JUMP)) {
		endpc = ins->address + ins->size;
		goto out;
	    }
	    if(ins->id == X86_INS_INT3) {
		return nullptr;
	    }
	}
	curpc += (uint64_t)codeptr - (uint64_t)code;
	remain += PAGE_SIZE;
    }

out:
    
    block = new uint8_t[endpc - pc.rawpc];
    mem_read(block,pc.rawpc,endpc - pc.rawpc);

    ret = translate(block,pc,endpc - pc.rawpc);

    delete[] block;
    cs_free(ins,1);
    return ret;
}

AddrSpace::AddrSpace(Context *_ctx,const refSnapshot &_snap)
    : ctx(_ctx),snap(_snap)
{
    mem = BytMem::create_var(ctx);
    //TODO initialize memory layout
}
int AddrSpace::read(refState state,uint8_t *buf,uint64_t pos,size_t len) {
    //assume executable page is read only
    //TODO check page
    return snap->mem_read(buf,pos,len);
}
int AddrSpace::handle_select(const uint64_t idx,const unsigned int size) {
    int ret = 0;
    uint64_t pos,base;
    unsigned int off;
    uint8_t buf[1];
    refBytVec val;
    std::map<uint64_t,MemPage>::iterator page_it;

    assert(size % 8 == 0);

    dbg("read idx %016lx\n",idx);

    pos = idx;
    while(pos < (idx + size / 8)) {
	base = pos & ~(PAGE_SIZE - 1);
	off = pos & (PAGE_SIZE - 1);

	page_it = page_map.find(base);
	if(page_it == page_map.end()) {
	    //err("page out bound\n");
	    //for test
	    auto page = MemPage(base,PROT_READ | PROT_WRITE);
	    page_it = page_map.insert(std::make_pair(base,page)).first;
	}

	auto &page = page_it->second;
	for(; off < PAGE_SIZE && pos < (idx + size / 8); off++,pos++) {
	    if(page.dirty.test(off)) {
		continue;
	    }

	    if(pos < 0x3000) {
		//for test
		//val = BytVec::create_imm(8,0xb);
		//page.symbol.reset(off);
		val = BytVec::create_var(8,ctx);
		mem_symbol[pos] = val;
		page.symbol.set(off);
	    } else {
		if(snap->mem_read(buf,pos,sizeof(*buf))) {
		    info("read page failed\n");
		    //TODO return read error
		    continue;
		}
		val = BytVec::create_imm(8,buf[0]);
		page.symbol.reset(off);
	    }

	    mem_constr.insert(cond_eq(
			expr_select(mem,BytVec::create_imm(32,pos),8),
			val));

	    page.dirty.set(off);
	    ret += 1;
	}
    }
    return ret;
}
/*
std::vector<refOperator> AddrSpace::source_select(
	const refOperator &sel,
	const std::unordered_map<refExpr,uint64_t> &var
	) const {
    std::vector<refOperator> retseq;
    refExpr mem;
    uint64_t base;
    uint64_t idx;

    assert(sel->type == ExprOpSelect);

    auto base_it = var.find(sel->operand[1]);
    assert(base_it != var.end());
    mem = sel->operand[0];
    base = base_it->second;

    while(mem->type != ExprMem) {
	assert(mem->type == ExprOpStore);
	auto str = std::static_pointer_cast<Operator>(mem);
	auto idx_it = var.find(str->operand[1]);
	assert(idx_it != var.end());
	idx = idx_it->second;

	if(idx == base) {
	    retseq.push_back(str);
	    break;
	}

	mem = str->operand[0];
    }

    return retseq;
}
*/
