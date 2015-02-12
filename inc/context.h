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
#define PAGE_PROBE	0x8
#define PAGE_SIZE 	0x1000

namespace symx {
	class ProgCtr {
		public:
			const uint64_t rawpc;
			const int insmd;
			ProgCtr(const uint64_t _rawpc,const int _insmd)
				: rawpc(_rawpc),insmd(_insmd) {}
			bool operator==(const ProgCtr &other) const {
				return rawpc == other.rawpc && \
					insmd == other.insmd;
			}
	};
};
namespace std {
	template<>
	struct hash<symx::ProgCtr> {

		std::size_t operator()(const symx::ProgCtr &key) const {
			return (key.rawpc << 8) | key.insmd; 
		}
	};
};
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
	typedef std::shared_ptr<Block> refBlock;
	
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
			virtual int get_insmd() = 0;
			virtual std::vector<MemPage> get_mem_map() = 0;
	};
	class Context {
		public:
			csh cs;
			Solver *solver;
			const unsigned int REGSIZE;
			const unsigned int NUMREG;
			const unsigned int NUMFLAG;
			const unsigned int REGIDX_PC;
			uint64_t last_var_id;
			std::queue<std::shared_ptr<State>> state;
			std::unordered_map<ProgCtr,refBlock> block;

			Context(
				Solver *_solver,
				const unsigned int _REGSIZE,
				const unsigned int _NUMREG,
				const unsigned int _NUMFLAG,
				const unsigned int _REGIDX_PC
			) :
				solver(_solver),
				REGSIZE(_REGSIZE),
				NUMREG(_NUMREG),
				NUMFLAG(_NUMFLAG),
				REGIDX_PC(_REGIDX_PC),
				last_var_id(0) {}
			virtual refBlock interpret(
				refProbe probe,
				const ProgCtr &pc) = 0;
	};
};

#endif
