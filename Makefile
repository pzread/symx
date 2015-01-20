default:
	clang++ -O2 -std=c++11 -o bin/symx -I . -I src -lcapstone \
		src/expr.cpp \
		src/state.cpp \
		src/symx.cpp \
		src/utils.cpp \
		arch/arm/arm.cpp
