// gcc -msse4.1 -msha supported.c -o supported.so


#include <cpuid.h>
#include <stdio.h>
#include <stdint.h>

int main(void) {
    unsigned int eax, ebx, ecx, edx;
    unsigned int leaf, subleaf;
    // eax = 7;
    // ecx = 0;
    //   asm volatile ("cpuid"
    //    :"=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
    //    :"a"(eax), "c"(ecx)
    //   );
    
    leaf = 7;
    subleaf = 0;
    if (!__get_cpuid_count(leaf, subleaf, &eax, &ebx, &ecx, &edx))
    {
        printf("__get_cpuid failed\n");
        return 2;
    }
    // bit_SHA
    printf ("ebx: %X\n", ebx);
    if ((ebx >> 29) & 1) {
        printf("Intel SHA extensions supported\n");
        return 0;
    } else {
        printf("Intel SHA extensions not supported\n");
        return 2;
    }
}
