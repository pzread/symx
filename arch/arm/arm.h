#include<stdint.h>
#include<unistd.h>
#include<vector>

#include"context.h"
#include"state.h"

#ifndef _ARM_H_
#define _ARM_H_

#define ARM_REG_SIZE	4
#define ARM_FLAG_NUM	4
#define ARM_SR_N	0
#define ARM_SR_Z	1
#define ARM_SR_C	2
#define ARM_SR_V	3

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
		uint64_t read_reg(const unsigned int regid,bool *symbol);
		bool read_flag(const unsigned int flagid);
		ssize_t read_mem(
			const uint64_t addr,
			const uint8_t *buf,
			const size_t len);
		int get_insmd();
		std::vector<symx::MemPage> get_mem_map();
};
class ARMContext : public symx::Context {
	public:
		ARMContext(symx::Solver *solver);
		symx::refBlock interpret(
			symx::refProbe _probe,
			const symx::ProgCtr &pc);
};

int initialize();

};

#endif
