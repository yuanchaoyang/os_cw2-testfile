#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

struct addr_space_info {
    unsigned long num_vmas, num_anon, num_file, num_w_and_x;
    unsigned long total_mapped, total_resident, largest_gap;
    unsigned long stack_size, heap_size;
};

int main() {
    struct addr_space_info info;
    long ret = syscall(463, 0, &info);
    if (ret != 0) {
        printf("FAIL ret=%ld\n", ret);
        return 1;
    }
    printf("vmas=%lu anon=%lu file=%lu wx=%lu\n",
        info.num_vmas, info.num_anon, info.num_file, info.num_w_and_x);
    printf("mapped=%lu resident=%lu gap=%lu\n",
        info.total_mapped, info.total_resident, info.largest_gap);
    printf("stack=%lu heap=%lu\n", info.stack_size, info.heap_size);
    if (info.num_vmas == 0)
        printf("FAIL: num_vmas=0\n");
    else if (info.num_anon + info.num_file != info.num_vmas)
        printf("FAIL: anon+file != vmas\n");
    else if (info.stack_size == 0)
        printf("FAIL: stack_size=0\n");
    else if (info.total_mapped == 0)
        printf("FAIL: total_mapped=0\n");
    else
        printf("PASS\n");
    return 0;
}
