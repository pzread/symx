default:
	clang++ -Wall -Wextra -Wno-unused-parameter -O2 -std=c++11 -o bin/symx -I . -I src -lcapstone \
		src/expr.cpp \
		src/state.cpp \
		src/utils.cpp \
		arch/arm/arm.cpp \
		src/symx.cpp
