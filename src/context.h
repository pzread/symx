#include<stdint.h>
#include<capstone/capstone.h>
#include<memory>
#include<vector>
#include<map>

#ifndef _CONTEXT_H_
#define _CONTEXT_H_

namespace symx {
	using namespace symx;

	class State;
	class Block;
	class Probe;
	typedef std::shared_ptr<Probe> refProbe;

	class Probe {
		public:
			virtual uint64_t read_reg(const unsigned int regid) = 0;
			virtual bool read_flag(const unsigned int flagid) = 0;
			virtual ssize_t read_mem(
				const uint64_t addr,
				const uint8_t *buf,
				const size_t len
			) = 0;
	};
	class Context {
		public:
			csh cs;
			uint64_t last_var_id;
			unsigned int reg_size;
			unsigned int num_reg;
			unsigned int num_flag;
			Context() : last_var_id(0) {}

			std::vector<std::shared_ptr<State>> state;
			std::map<uint64_t,std::shared_ptr<Block>> block;
	};
};

#endif
