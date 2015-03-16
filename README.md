# symx
Lightweight Symbolic Execution Engine

# compile
### Z3
```
cd z3
python scripts/mk_make.py
cd build
make
sudo make install
```
### Capstone Engine
```
cd capstone
./make.sh
sudo make install
```
### symx
```
cd bin
cmake ..
make
```

#todo
1. ELF loader (For now, need to hardcode symx.cpp and arch/arm.cpp)
