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

#endif
