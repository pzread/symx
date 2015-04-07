#include<stdint.h>
#include<unistd.h>
#include<vector>

#include"context.h"
#include"state.h"

#ifndef _OPENREIL_H_
#define _OPENREIL_H_

#define OPENREIL_REG_SIZE	4
#define OPENREIL_FLAG_NUM	6

namespace arm {

using namespace arm;

class ARMProbe;
typedef std::shared_ptr<ARMProbe> refARMProbe;

class ARMProbe : public symx::Probe {
	public:
		pid_t pid;
		uint8_t *bin;
		uint64_t off;

		ARMProbe(pid_t _pid,int fd,uint64_t _off);
		uint64_t read_reg(const unsigned int regid,bool *symbol) const;
		bool read_flag(const unsigned int flagid) const;
		ssize_t read_mem(
			const uint64_t addr,
			const uint8_t *buf,
			const size_t len) const;
		int get_insmd() const;
		std::vector<symx::MemPage> get_mem_map() const;
};
class ARMContext : public symx::Context {
	public:
		ARMContext(symx::Solver *solver);
		symx::refBlock interpret(
			const symx::refProbe &_probe,
			const symx::ProgCtr &pc);
};

int initialize();

};

#endif
