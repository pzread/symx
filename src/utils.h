#include<stdio.h>
#include<unistd.h>
#include<memory>

#ifndef _UTILS_H_
#define _UTILS_H_

#define err(x,...) {fprintf(stderr,"[%d][" LOG_PREFIX "] " x,getpid(),##__VA_ARGS__);while(1);}
#define info(x,...) {fprintf(stderr,"[%d][" LOG_PREFIX "] " x,getpid(),##__VA_ARGS__);}

template<typename T,typename... Args>
std::shared_ptr<T> ref(Args&&... args)
{
	return std::make_shared<T>(std::forward<Args>(args)...);
}

#endif
