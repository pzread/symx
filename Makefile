default:
	clang++ -O2 -std=c++1y -o bin/symx -I . -I src -lcapstone \
		src/expr.cpp \
		src/state.cpp \
		src/symx.cpp \
		arch/arm/arm.cpp
