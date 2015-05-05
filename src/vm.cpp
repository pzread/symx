#define LOG_PREFIX "vm"

#define LINUX
#define X86_32

#include<stdint.h>
#include<unistd.h>

extern "C" {
#include<dr_api.h>
#include<dr_inject.h>
#include<dr_config.h>
}

#include"utils.h"
#include"vm.h"

using namespace vm;

int VirtualMachine::Create(
	const char *container_path,
	const char *exe_path,
	const char **argv
) {
    void *data;
    process_id_t pid;
    
    if(dr_inject_process_create(exe_path,argv,&data)) {
	return -1;
    }
    pid = dr_inject_get_process_id(data);

    printf("%d\n",dr_register_process(
	    exe_path,
	    pid,
	    false,
	    "../dynamorio",
	    DR_MODE_CODE_MANIPULATION,
	    false,
	    DR_PLATFORM_64BIT,
	    ""));
    printf("%d\n",dr_register_client(
	    exe_path,
	    pid,
	    false,
	    DR_PLATFORM_64BIT,
	    0,
	    0,
	    "./libdyntrac.so",
	    ""));

    if(!dr_inject_process_inject(data,false,NULL)) {
	return -1;
    }

    dr_inject_process_run(data);
    dr_inject_wait_for_child(data,0);
    dr_inject_process_exit(data,true);

    info("VM create: %s %s\n",container_path,exe_path);
    return 0;
}
int VirtualMachine::Continue(uint64_t pc) {
    return 0;
}
