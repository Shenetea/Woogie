// clang -O2 -fPIC -c moving_target.c -o moving_target.o
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/mman.h>
#include <linux/perf_event.h>
#include <bpf/bpf.h>          // libbpf-dev
#include <bpf/libbpf.h>

/* -------------- 1.  API that the attacker wants to hook --------------- */
typedef void (*handler_t)(int);
extern handler_t __start_ibstubs, __stop_ibstubs;   // linker created

/* five identical stubs, each with a different ENDBR immediate */
#define STUBS 5
__attribute__((section("ibstubs"), aligned(64)))
void stub0(int x){ asm volatile("nop; endbr64; .long 0xdead0000"); printf("stub0 %d\n",x); }
__attribute__((section("ibstubs"), aligned(64)))
void stub1(int x){ asm volatile("nop; endbr64; .long 0xdead0001"); printf("stub1 %d\n",x); }
__attribute__((section("ibstubs"), aligned(64)))
void stub2(int x){ asm volatile("nop; endbr64; .long 0xdead0002"); printf("stub2 %d\n",x); }
__attribute__((section("ibstubs"), aligned(64)))
void stub3(int x){ asm volatile("nop; endbr64; .long 0xdead0003"); printf("stub3 %d\n",x); }
__attribute__((section("ibstubs"), aligned(64)))
void stub4(int x){ asm volatile("nop; endbr64; .long 0xdead0004"); printf("stub4 %d\n",x); }

handler_t stubs[STUBS] = {stub0,stub1,stub2,stub3,stub4};

/* global pointer that the program (and attacker) use */
volatile handler_t current_handler = stub0;

/* ---------------- 2.  Game loop --------------------------------------- */
int main(void)
{
    puts("[+] moving-target PoC – press Ctrl-C to quit");
    /* preload BPF program (see below) */
    if (system("sudo ./loader moving_target.o &") != 0)
        puts("[-] loader failed – running without BPF guard");

    int cookie = 0;
    for (;;){
        current_handler(cookie++);          // indirect call
        usleep(100*1000);                   // 10 Hz game tick
    }
}
