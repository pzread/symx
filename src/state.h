#include<memory>
#include"expr.h"
#include"solver.h"

#ifndef _STATE_H_
#define _STATE_H_

class State {
	public:
		std::shared_ptr<Mem> mem;
		std::shared_ptr<Expr> reg[64];
		std::shared_ptr<Cond> flag[64];
};

#endif
