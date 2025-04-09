#pragma once

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "rocksdb/rocksdb_namespace.h"

// Set DEBUG to 1 to enable debug prints
#define DEBUG 1

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
    struct bpf_object *obj = NULL;
};

class CachestreamTidGuard {
 public:
  CachestreamTidGuard(Cachestream& cs, int thread_id)
      : cachestream_(cs), tid_(thread_id), removed_(false) {
    cachestream_.add_tgid(tid_);
  }

  ~CachestreamTidGuard() {
    remove();
  }

  void remove() {
    if (!removed_) {
      cachestream_.remove_tgid(tid_);
      removed_ = true;
    }
  }

  CachestreamTidGuard(const CachestreamTidGuard&) = delete;
  CachestreamTidGuard& operator=(const CachestreamTidGuard&) = delete;
  CachestreamTidGuard(CachestreamTidGuard&&) = delete;
  CachestreamTidGuard& operator=(CachestreamTidGuard&&) = delete;

 private:
  Cachestream& cachestream_;
  int tid_;
  bool removed_;
};

} // namespace ROCKSDB_NAMESPACE
