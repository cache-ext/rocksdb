#ifndef CACHESTREAM_H
#define CACHESTREAM_H

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "rocksdb/rocksdb_namespace.h"


#define HAPPYCACHE_PATH "/mydata/rocksdb/happycache/happycache.bpf.o"
#define CS_ENV "CACHESTREAM_PATH"


namespace ROCKSDB_NAMESPACE {

class Cachestream {
public:
    static Cachestream& getInstance() {
        static Cachestream instance;
        return instance;
    }

    Cachestream(const Cachestream&) = delete;
    Cachestream& operator=(const Cachestream&) = delete;

    void add_tgid(int tgid);
    void remove_tgid(int tgid);

private:
    Cachestream();
    ~Cachestream();
    int load_bpf_program();
    int join_cgroup();

    int prog_fd = -1;
    int map_fd = -1;
    int cgroup_fd = -1;
    struct bpf_link *link = NULL;
    struct bpf_object *obj = NULL;
};

} // namespace ROCKSDB_NAMESPACE

#endif // CACHESTREAM_H
