#include<stdio.h>
#include<unistd.h>
#include<memory>

#ifndef _UTILS_H_
#define _UTILS_H_

#define err(fmt,...) internal_err(LOG_PREFIX,fmt,##__VA_ARGS__)
#define info(fmt,...) internal_info(LOG_PREFIX,fmt,##__VA_ARGS__)
#define dbg(fmt,...) internal_dbg(LOG_PREFIX,fmt,##__VA_ARGS__)

void internal_err(const char *prefix,const char *fmt,...);
void internal_info(const char *prefix,const char *fmt,...);
void internal_dbg(const char *prefix,const char *fmt,...);

template<typename T,typename... Args>
std::shared_ptr<T> ref(Args&&... args)
{
	return std::make_shared<T>(std::forward<Args>(args)...);
}

//Predefine
namespace symx {
    class Context;
    class VirtualMachine;
    class Snapshot;
    class AddrSpace;
    class Block;
    class State;
    class ProgCtr;
    class MemRecord;
    typedef std::shared_ptr<const Snapshot> refSnapshot;
    typedef std::shared_ptr<AddrSpace> refAddrSpace;
    typedef std::shared_ptr<Block> refBlock;
    typedef std::shared_ptr<State> refState;
    typedef std::shared_ptr<const MemRecord> refMemRecord;
}

#endif
