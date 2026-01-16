#include <bpf/libbpf.h>
#include <unistd.h>
int main(int argc,char **argv){
    struct bpf_object *obj = bpf_object__open_file("roll.bpf.o",NULL);
    bpf_object__load(obj);
    struct bpf_program *prog = bpf_object__find_program_by_name(obj,"roll_token");
    int fd = bpf_program__fd(prog);
    /* attach to generic tracepoint – runs every 250 ms */
    system("echo 1 >/sys/kernel/debug/tracing/events/syscalls/sys_enter_nanosleep/enable");
    printf("[+] BPF attached, token rolling every 250 ms\n");
    pause();
    return 0;
}
