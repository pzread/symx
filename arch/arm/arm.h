#include<stdint.h>

#include"context.h"
#include"state.h"

#ifndef _ARM_H_
#define _ARM_H_

#define ARM_REG_SIZE 4
#define ARM_FLAG_NUM 4
#define ARM_SR_N 0
#define ARM_SR_Z 1
#define ARM_SR_C 2
#define ARM_SR_V 3

namespace arm {

using namespace arm;

class ARMProbe;
typedef std::shared_ptr<ARMProbe> refARMProbe;

class ARMProbe : public symx::Probe {
	public:
		uint8_t *bin;
		uint64_t off;
		ARMProbe(const int fd,const uint64_t _off);
		uint64_t read_reg(const unsigned int regid,bool *symbol);
		bool read_flag(const unsigned int flagid);
		ssize_t read_mem(
			const uint64_t addr,
			const uint8_t *buf,
			const size_t len
		);
};
class ARMContext : public symx::Context {
	public:
		ARMContext(symx::Solver *solver);
		symx::refBlock interpret(
			symx::refProbe _probe,
			uint64_t pc);
};

int initialize();

};

#endif
