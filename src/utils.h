#include<stdio.h>
#include<unistd.h>
#include<memory>

#ifndef _UTILS_H_
#define _UTILS_H_

#define err(...) internal_err(LOG_PREFIX,##__VA_ARGS__)
#define info(...) internal_info(LOG_PREFIX,##__VA_ARGS__)

void internal_err(std::string prefix,std::string fmt,...);
void internal_info(std::string prefix,std::string fmt,...);

template<typename T,typename... Args>
std::shared_ptr<T> ref(Args&&... args)
{
	return std::make_shared<T>(std::forward<Args>(args)...);
}

#endif
