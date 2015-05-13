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
