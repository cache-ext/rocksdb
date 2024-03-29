#include "cachestream.h"

#include <iostream>
#include <string>


namespace ROCKSDB_NAMESPACE {

int Cachestream::join_cgroup() {
    const char* cgroup_path = getenv(CS_ENV);
    if (!cgroup_path) {
        return -1;
    }
    std::string cgroup_procs_path = std::string(cgroup_path) + "/cgroup.procs";

    int cg_fd = open(cgroup_procs_path.c_str(), O_WRONLY);
    if (cg_fd < 0) {
        perror("open");
        exit(1);
    }

    pid_t pid = getpid();
    if (dprintf(cg_fd, "%d\n", pid) < 0) {
        perror("dprintf");
        close(cg_fd);
        exit(1);
    }
    return cg_fd;
}

int Cachestream::load_bpf_program() {
    struct bpf_program *prog;
    
    obj = bpf_object__open_file("happycache.bpf.o", NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		return -1;
	}

    struct bpf_map *tid_map;
    tid_map = bpf_object__find_map_by_name(obj, "tids");
    if (libbpf_get_error(tid_map)) {
        fprintf(stderr, "ERROR: finding BPF map failed\n");
        return -1;
    }

    map_fd = bpf_map__fd(tid_map);

    prog = bpf_object__next_program(obj, NULL);
	if (!prog) {
		bpf_object__close(obj);
		fprintf(stderr, "ERROR: finding BPF program failed\n");
		return -1;
	}

    if (bpf_program__type(prog) != BPF_PROG_TYPE_CGROUP_CACHESTREAM) {
		bpf_program__set_type(prog, BPF_PROG_TYPE_CGROUP_CACHESTREAM);
	}

    if (bpf_object__load(obj)) {
		bpf_object__close(obj);
		fprintf(stderr, "ERROR: loading BPF program failed\n");
		return -1;
	}

    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
		bpf_object__close(obj);
		fprintf(stderr, "ERROR: getting BPF program FD failed\n");
        return -1;
	}

    if (bpf_prog_attach(prog_fd, cgroup_fd, BPF_CGROUP_CACHESTREAM, 0)) {
		bpf_object__close(obj);
		perror("Failed to attach DEV_CGROUP program");
		return -1;
	}

    return 0;
}

Cachestream::Cachestream() {
    if ((cgroup_fd = join_cgroup()) == -1) {
        std::cerr << CS_ENV << " not set, running vanilla" << std::endl;
        return;
    }

    if (load_bpf_program() < 0) {
        std::cerr << "Failed to load BPF program" << std::endl;
        close(cgroup_fd);
        exit(1);
    }
}

Cachestream::~Cachestream() {
    if (cgroup_fd != -1) {
        close(cgroup_fd);
    }
    if (prog_fd != -1) {
        close(prog_fd);
    }
    if (obj) {
        bpf_object__close(obj);
    }
}

void Cachestream::add_tgid(int tgid) {
    // noop if not setup
    if (cgroup_fd == -1) {
        return;
    }

    __u64 key = tgid;
    __u8 value = 1;
    int ret = bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
    if (ret < 0) {
        perror("bpf_map_update_elem");
        std::cerr << "Failed to add tgid to map" << std::endl;
    }
}

void Cachestream::remove_tgid(int tgid) {
    // noop if not setup
    if (cgroup_fd == -1) {
        return;
    }

    __u64 key = tgid;
    int ret = bpf_map_delete_elem(map_fd, &key);
    if (ret < 0) {
        perror("bpf_map_delete_elem");
        std::cerr << "Failed to remove tgid from map" << std::endl;
    }
}

} // namespace ROCKSDB_NAMESPACE