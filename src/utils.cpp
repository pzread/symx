#include<stdio.h>
#include<stdarg.h>
#include<unistd.h>
#include<string>
#include"utils.h"

void internal_err(std::string prefix,std::string fmt,...) {
	va_list args;
	std::string cfmt;

	cfmt = "[" + std::to_string(getpid()) + "][" + prefix + "]\t" + fmt;
	va_start(args,fmt);
	vfprintf(stderr,cfmt.c_str(),args);
	va_end(args);
	while(1);
}
void internal_info(std::string prefix,std::string fmt,...) {
	va_list args;
	std::string cfmt;

	cfmt = "[" + std::to_string(getpid()) + "][" + prefix + "]\t" + fmt;
	va_start(args,fmt);
	vfprintf(stderr,cfmt.c_str(),args);
	va_end(args);
}
void internal_dbg(std::string prefix,std::string fmt,...) {
	va_list args;
	std::string cfmt;

	cfmt = "\e[1;31m[" + std::to_string(getpid()) + "][" + prefix + "]\e[m\t" + fmt;
	va_start(args,fmt);
	vfprintf(stderr,cfmt.c_str(),args);
	va_end(args);
}
