#include<stdint.h>
#include<capstone/capstone.h>
#include<memory>
#include<queue>
#include<unordered_map>

#ifndef _CONTEXT_H_
#define _CONTEXT_H_

namespace symx {
	using namespace symx;

	class State;
	class Block;
	class Probe;
	class SolverExpr;
	class SolverCond;
	class TransVisitor;
	typedef std::shared_ptr<SolverExpr> refSolverExpr;
	typedef std::shared_ptr<SolverCond> refSolverCond;
	typedef std::shared_ptr<Probe> refProbe;

	class Solver {
		public:
			virtual TransVisitor* create_translator() = 0;
			virtual TransVisitor* create_translator(
					const refSolverExpr mem,
					const std::unordered_map
						<unsigned int,
						refSolverExpr> &reg,
					const std::unordered_map
						<unsigned int,
						refSolverCond> &flag
				) = 0;
	};
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
			Solver *solver;
			const unsigned int reg_size;
			const unsigned int num_reg;
			const unsigned int num_flag;
			const unsigned int regidx_pc;
			uint64_t last_var_id;
			std::queue<std::shared_ptr<State>> state;
			std::unordered_map
				<uint64_t,std::shared_ptr<Block> > block;

			Context(
				Solver *_solver,
				const unsigned int _reg_size,
				const unsigned int _num_reg,
				const unsigned int _num_flag,
				const unsigned int _regidx_pc
			) :
				solver(_solver),
				reg_size(_reg_size),
				num_reg(_num_reg),
				num_flag(_num_flag),
				regidx_pc(_regidx_pc),
				last_var_id(0) {}
			virtual std::shared_ptr<Block> interpret(
				std::shared_ptr<Probe> probe,
				uint64_t pc) = 0;
	};
};

#endif
