default:
	clang++ -O2 -std=c++11 -o bin/symx -I src -lcapstone \
		src/expr.cpp \
		src/symx.cpp
