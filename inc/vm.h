#include<stdint.h>
#include<unistd.h>
#include<limits.h>
#include<semaphore.h>

#ifndef _VM_H_
#define _VM_H_

#define UNIX_PATH_MAX		108
#define VMCOM_EVT_ENTER		1
#define VMCOM_EVT_EXECUTE	2
#define VMCOM_EVT_RET		10

namespace vm {
    struct vmcom_context {
	uint64_t pc;
    };
    struct vmcom_frame {
	int evt;
	union {
	    struct vmcom_context context;    
	};
    };

    class VirtualMachine {
	private:
	    char name[NAME_MAX + 1];
	    pid_t pid;
	    void *data;
	    int com_evt;
	    struct vmcom_frame *com_mem;

	    int vmcom_create();
	    int vmcom_accept(int listen_fd);

	public:
	    int create(
		    const char *container_path,
		    const char *exe_path,
		    const char **argv);
	    int destroy();

	    int event_wait();
	    int event_ret();
	    int event_get_context();
    };
}

#endif
