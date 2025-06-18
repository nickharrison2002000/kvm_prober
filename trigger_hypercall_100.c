#include <stdio.h>
#include <stdint.h>

int main() {
    uint64_t rax;
    asm volatile (
        "mov $100, %%rax\n"
        "vmmcall\n"
        : "=a" (rax)
    );
    printf("Write Flag Value: 0x%lx\n", rax);
}
