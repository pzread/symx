#include<stdlib.h>
#include<stdint.h>
#include<string.h>
#include<stddef.h>
#include<fcntl.h>
#include<limits.h>
#include<sys/socket.h>
#include<sys/un.h>
#include<sys/mman.h>

#define LINUX
#define X86_32
extern "C" {
    #include<dr_api.h>
}

#include"vm.h"

using namespace symx;

static char name[NAME_MAX + 1];
static int com_evt;
static struct vmcom_frame *com_mem;

static void event_exit();
static void event_thread_init(void *drctx);
static dr_emit_flags_t event_basic_block(
	void *drctx,
	void *tag,
	instrlist_t *bb,
	bool for_trace,
	bool translating);
static void call_basic_block(app_pc pc);
static int com_push(int evt);
static int com_loop();

DR_EXPORT void dr_init(client_id_t id) {
    char mem_path[PATH_MAX + 1];
    int mem_fd;
    char event_path[PATH_MAX + 1];
    struct sockaddr_un addr;
    socklen_t addrlen;

    strncpy(name,dr_get_options(id),sizeof(name) - 1);

    snprintf(mem_path,sizeof(mem_path),"%s_mem",name);
    mem_fd = open(mem_path,O_RDWR);
    com_mem = (struct vmcom_frame*)mmap(
	    NULL,
	    sizeof(struct vmcom_frame),
	    PROT_READ | PROT_WRITE,
	    MAP_SHARED,
	    mem_fd,
	    0);
    close(mem_fd);
    
    snprintf(event_path,sizeof(event_path),"%s_event",name);
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path,event_path,UNIX_PATH_MAX - 1);
    com_evt = socket(AF_UNIX,SOCK_STREAM,0);
    addrlen = offsetof(struct sockaddr_un,sun_path) + strlen(addr.sun_path);
    connect(com_evt,(struct sockaddr*)&addr,addrlen);

    dr_register_exit_event(event_exit);
    dr_register_thread_init_event(event_thread_init);
    dr_register_bb_event(event_basic_block);
}

static void event_exit() {
    munmap(com_mem,sizeof(vmcom_frame));
    close(com_evt);
}
static void event_thread_init(void *drctx) {
    com_push(VMCOM_EVT_ENTER);
    com_loop();
}
static dr_emit_flags_t event_basic_block(
	void *drctx,
	void *tag,
	instrlist_t *bb,
	bool for_trace,
	bool translating
) {
    dr_insert_clean_call(
	    drctx,
	    bb,
	    instrlist_first(bb),
	    (void*)call_basic_block,
	    false,
	    1,
	    OPND_CREATE_INT32(dr_fragment_app_pc(tag)));
    return DR_EMIT_DEFAULT;
}
static void call_basic_block(app_pc pc) {
    void *drctx = dr_get_current_drcontext();
    dr_mcontext_t ctx;

    com_mem->context.pc = (uint32_t)pc;
    ctx.size = sizeof(ctx);
    ctx.flags = DR_MC_CONTROL;
    if(dr_get_mcontext(drctx,&ctx)) {
	com_mem->context.reg[REGIDX_EAX] = ctx.eax;
	com_mem->context.reg[REGIDX_EBX] = ctx.ebx;
	com_mem->context.reg[REGIDX_ECX] = ctx.ecx;
	com_mem->context.reg[REGIDX_EDX] = ctx.edx;
	com_mem->context.reg[REGIDX_EDI] = ctx.edi;
	com_mem->context.reg[REGIDX_ESI] = ctx.esi;
	com_mem->context.reg[REGIDX_EBP] = ctx.ebp;
	com_mem->context.reg[REGIDX_ESP] = ctx.esp;
	com_mem->context.flag = ctx.eflags;
    }

    com_push(VMCOM_EVT_EXECUTE);
    com_loop();
}

static int com_push(int evt) {
    com_mem->evt = evt;
    write(com_evt,&evt,sizeof(evt));
    return 0;
}
static int com_loop() {
    int evt;
    while(read(com_evt,&evt,sizeof(evt)) > 0) {
	switch(evt) {
	    case VMCOM_EVT_READMEM:
		memcpy(
			com_mem->membuf.buf,
			(void*)com_mem->membuf.pos,
			com_mem->membuf.len);
		com_push(VMCOM_EVT_READMEM);
	    case VMCOM_EVT_RET:
		return 0;
	}
    }
    return 0;
}
