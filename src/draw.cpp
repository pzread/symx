#define LOG_PREFIX "draw"

#include<string.h>
#include<graphviz/cgraph.h>
#include"utils.h"
#include"draw.h"

using namespace symx;

Draw::Draw() {
	g = agopen((char*)"flow",Agdirected,NULL);
	agattr(g,AGNODE,(char*)"shape",(char*)"box");
	agattr(g,AGNODE,(char*)"label",(char*)"");
	agattr(g,AGNODE,(char*)"labelfloat",(char*)"Monospace");
}
Draw::~Draw() {
	agclose(g);
}

int Draw::output(const char *filename) {
	FILE *f = fopen(filename,"w");
	agwrite(g,f);
	fclose(f);
	return 0;
}
int Draw::update_link(uint64_t from,uint64_t to) {
	auto fromit = record.find(from);
	if(fromit == record.end()) {
		add_block(from);
		fromit = record.find(from);
	}
	auto toit = record.find(to);
	if(toit == record.end()) {
		add_block(to);
		toit = record.find(to);
	}
	agedge(g,fromit->second,toit->second,(char*)"",TRUE);
	return 0;
}
int Draw::update_block(uint64_t pos,char *data) {
	auto blkit = record.find(pos);
	if(blkit == record.end()) {
		add_block(pos);
		blkit = record.find(pos);
	}
	agset(blkit->second,(char*)"label",agstrdup(g,data));
	return 0;
}
int Draw::add_block(uint64_t pos) {
	Agnode_t *node;
	char name[512];
	snprintf(name,sizeof(name) - 1,"0x%08lx",pos);
	node = agnode(g,name,TRUE);
	record[pos] = node;
	return 0;
}
