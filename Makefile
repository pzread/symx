default:
	clang++ -Wall -Wextra -Wno-unused-parameter -O2 -std=c++11 -o bin/symx \
		-I . \
		-I src \
		-lcapstone -lz3 \
		src/expr.cpp \
		src/state.cpp \
		src/utils.cpp \
		src/solver.cpp \
		arch/arm/arm.cpp \
		solver/z3.cpp \
		src/symx.cpp
