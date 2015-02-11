#include<stdint.h>
#include<capstone/capstone.h>
#include<memory>
#include<queue>
#include<vector>
#include<unordered_map>
#include<unordered_set>

#ifndef _CONTEXT_H_
#define _CONTEXT_H_

#define PAGE_READ	0x1
#define PAGE_WRITE	0x2
#define PAGE_EXEC	0x4
#define PAGE_SIZE 	0x1000

namespace symx {
	using namespace symx;

	class MemPage;
	class State;
	class Block;
	class Probe;
	class SolvExpr;
	class SolvCond;
	class TransVisitor;
	typedef std::shared_ptr<SolvExpr> refSolvExpr;
	typedef std::shared_ptr<SolvCond> refSolvCond;
	typedef std::shared_ptr<Probe> refProbe;

	class Solver {
		public:
			virtual TransVisitor* create_translator() = 0;
			virtual bool solve(
				const std::unordered_set<refSolvCond> &cons,
				std::unordered_map<refSolvExpr,uint64_t> *var
			) = 0;
	};
	class Probe {
		public:
			virtual uint64_t read_reg(
				const unsigned int regid,
				bool *symbol) = 0;
			virtual bool read_flag(const unsigned int flagid) = 0;
			virtual ssize_t read_mem(
				const uint64_t addr,
				const uint8_t *buf,
				const size_t len
			) = 0;
			virtual std::vector<MemPage> get_mem_map() = 0;
	};
	class Context {
		public:
			csh cs;
			Solver *solver;
			const unsigned int REGSIZE;
			const unsigned int num_reg;
			const unsigned int num_flag;
			const unsigned int REGIDX_PC;
			uint64_t last_var_id;
			std::queue<std::shared_ptr<State>> state;
			std::unordered_map
				<uint64_t,std::shared_ptr<Block> > block;

			Context(
				Solver *_solver,
				const unsigned int _REGSIZE,
				const unsigned int _num_reg,
				const unsigned int _num_flag,
				const unsigned int _REGIDX_PC
			) :
				solver(_solver),
				REGSIZE(_REGSIZE),
				num_reg(_num_reg),
				num_flag(_num_flag),
				REGIDX_PC(_REGIDX_PC),
				last_var_id(0) {}
			virtual std::shared_ptr<Block> interpret(
				std::shared_ptr<Probe> probe,
				uint64_t pc) = 0;
	};
};

#endif
