#include<stdint.h>
#include<graphviz/cgraph.h>
#include<unordered_map>

#ifndef _DRAW_H_
#define _DRAW_H_

namespace symx {

class Draw {
	public:
		Draw();
		~Draw();
		int update_link(uint64_t from,uint64_t to);
		int update_block(uint64_t pos,char *data);
		int output(const char *filename);
	private:
		Agraph_t *g;
		std::unordered_map<uint64_t,Agnode_t*> record;
		int add_block(uint64_t pos);
};

};

#endif
