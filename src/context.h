#include<stdint.h>
#include<capstone/capstone.h>

#ifndef _CONTEXT_H_
#define _CONTEXT_H_

class Context {
	public:
		csh cs;
		uint64_t last_var_id;
		unsigned int reg_size;
		unsigned int num_reg;
		unsigned int num_flag;
		Context() : last_var_id(0) {}
};

#endif
