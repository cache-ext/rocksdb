cd cachestream/bpf
make
cd ../..
LIB_MODE=shared make -j16 release
LIB_MODE=shared sudo make install
