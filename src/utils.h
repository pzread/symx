#include<memory>

#ifndef _UTILS_H_
#define _UTILS_H_

template<typename T,typename... Args>
std::shared_ptr<T> ref(Args&&... args)
{
	return std::make_shared<T>(std::forward<Args>(args)...);
}

#endif
