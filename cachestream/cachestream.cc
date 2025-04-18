#include "cachestream.h"

#include <iostream>
#include <string>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>


namespace ROCKSDB_NAMESPACE {

int Cachestream::join_cgroup() {
    const char* cgroup_path = getenv(CS_ENV);
    if (!cgroup_path || strlen(cgroup_path) == 0) {
#if DEBUG
        std::cerr << CS_ENV << " not set, running vanilla" << std::endl;
#endif
        return -1;
    }
    // open cgroup path as RDONLY
    int fd_cg = open(cgroup_path, O_RDONLY);
    if (fd_cg < 0) {
        std::cerr << "open: " << strerror(errno) << std::endl;
        exit(1);
    }
    std::string cgroup_procs_path = std::string(cgroup_path) + "/cgroup.procs";

    int fd_procs = open(cgroup_procs_path.c_str(), O_WRONLY);
    if (fd_procs < 0) {
        std::cerr << "open: " << strerror(errno) << std::endl;
        close(fd_cg);
        exit(1);
    }

    pid_t pid = getpid();
    if (dprintf(fd_procs, "%d\n", pid) < 0) {
        std::cerr << "dprintf: " << strerror(errno) << std::endl;
        close(fd_cg);
        close(fd_procs);
        exit(1);
    }

    close(fd_procs);

    std::cout << "joined cgroup: " << cgroup_path << std::endl;
    return fd_cg;
}

int Cachestream::load_bpf_program() {
    struct bpf_program *prog;

    obj = bpf_object__open_file(HAPPYCACHE_PATH, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file (%s) failed: %s\n",
                HAPPYCACHE_PATH, strerror(errno));
        return -1;
    }

    prog = bpf_object__find_program_by_name(obj, "happy_cache");
    if (!prog) {
        fprintf(stderr, "ERROR: finding BPF program 'happy_cache' failed\n");
        bpf_object__close(obj);
        return -1;
    }

    if (bpf_program__type(prog) != BPF_PROG_TYPE_CGROUP_CACHESTREAM) {
        bpf_program__set_type(prog, BPF_PROG_TYPE_CGROUP_CACHESTREAM);
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: loading BPF object failed: %s\n", strerror(errno)); // Added strerror
        bpf_object__close(obj);
        return -1;
    }

    map_fd = bpf_object__find_map_fd_by_name(obj, "tids");
    if (map_fd < 0) {
        fprintf(stderr, "ERROR: finding map FD for 'tids' failed: %s\n", strerror(errno)); // Added strerror
        bpf_object__close(obj);
        return -1;
    }

    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "ERROR: getting BPF program FD failed: %s\n", strerror(errno)); // Added strerror
        bpf_object__close(obj);
        close(map_fd);
        map_fd = -1;
        return -1;
    }

    // Print FDs
    std::cout << "prog_fd: " << prog_fd << std::endl;
    std::cout << "cgroup_fd: " << cgroup_fd << std::endl;
    std::cout << "map_fd: " << map_fd << std::endl;

    if (bpf_prog_attach(prog_fd, cgroup_fd, BPF_CGROUP_CACHESTREAM, 0)) {
        fprintf(stderr, "ERROR: Failed to attach BPF program: %s\n", strerror(errno));
        close(prog_fd);
        close(map_fd);
        prog_fd = -1;
        map_fd = -1;
        bpf_object__close(obj);
        return -1;
    }

    return 0;
}

Cachestream::Cachestream() {
    if ((cgroup_fd = join_cgroup()) == -1) {
#if DEBUG
        std::cerr << CS_ENV << " not set, running vanilla" << std::endl;
#endif
        return;
    }

    if (load_bpf_program() < 0) {
        std::cerr << "Failed to load BPF program" << std::endl;
        close(cgroup_fd);
        exit(1);
    }
}

Cachestream::~Cachestream() {
    if (prog_fd >= 0) {
        close(prog_fd);
    }
    if (map_fd >= 0) {
        close(map_fd);
    }
    if (cgroup_fd >= 0) {
        close(cgroup_fd);
    }
    if (obj) {
        bpf_object__close(obj);
    }
}
void Cachestream::add_tgid(int tgid) {
    // noop if not setup
    if (cgroup_fd == -1) {
#if DEBUG
        std::cerr << "cgroup not joined, skipping add_tgid" << std::endl;
#endif
        return;
    }

#if DEBUG
    std::cout << "adding tgid: " << tgid << std::endl;
#endif

    __u64 key = tgid;
    __u8 value = 1;
    int ret = bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
    if (ret < 0) {
        std::cerr << "bpf_map_update_elem: " << strerror(errno) << std::endl;
        std::cerr << "Failed to add tgid to map" << std::endl;
    }
}

void Cachestream::remove_tgid(int tgid) {
    // noop if not setup
    if (cgroup_fd == -1) {
#if DEBUG
        std::cerr << "cgroup not joined, skipping remove_tgid" << std::endl;
#endif
        return;
    }

#if DEBUG
    std::cout << "removing tgid: " << tgid << std::endl;
#endif

    __u64 key = tgid;
    int ret = bpf_map_delete_elem(map_fd, &key);
    if (ret < 0) {
        std::cerr << "bpf_map_delete_elem: " << strerror(errno) << std::endl;
        std::cerr << "Failed to remove tgid from map" << std::endl;
    }
}

} // namespace ROCKSDB_NAMESPACE
