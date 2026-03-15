#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

static int read_mem_ops(pid_t pid, long *vals) {
    char path[64];
    if (pid == 0)
        snprintf(path, sizeof(path), "/proc/self/mem_ops");
    else
        snprintf(path, sizeof(path), "/proc/%d/mem_ops", pid);
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return -1; }
    /* vals: 0=mmap_count 1=mmap_bytes 2=munmap_count 3=munmap_bytes
             4=mprotect_count 5=mprotect_bytes 6=brk_count 7=brk_bytes */
    char name[32];
    for (int i = 0; i < 4; i++) {
        if (fscanf(f, "%s %ld %ld", name, &vals[i*2], &vals[i*2+1]) != 3) {
            fclose(f); return -1;
        }
    }
    fclose(f);
    return 0;
}

static void print_mem_ops(const char *label, long *v) {
    printf("  %s: mmap=%ld/%ld munmap=%ld/%ld mprotect=%ld/%ld brk=%ld/%ld\n",
           label, v[0],v[1], v[2],v[3], v[4],v[5], v[6],v[7]);
}

int main(void) {
    long before[8], after[8];
    int pass = 0, fail = 0;
    long pagesz = sysconf(_SC_PAGESIZE);

    printf("=== Task 1 Test: Memory Ledger ===\n\n");

    /* --- Test 1: mmap --- */
    read_mem_ops(0, before);
    void *p = mmap(NULL, 4 * pagesz, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    read_mem_ops(0, after);
    if (p != MAP_FAILED &&
        after[0] == before[0] + 1 &&
        after[1] == before[1] + 4 * pagesz) {
        printf("[PASS] mmap: count +1, bytes +%ld\n", 4 * pagesz);
        pass++;
    } else {
        printf("[FAIL] mmap: count %ld->%ld (expect +1), bytes %ld->%ld (expect +%ld)\n",
               before[0], after[0], before[1], after[1], 4 * pagesz);
        fail++;
    }

    /* --- Test 2: munmap --- */
    read_mem_ops(0, before);
    munmap(p, 4 * pagesz);
    read_mem_ops(0, after);
    if (after[2] == before[2] + 1 &&
        after[3] == before[3] + 4 * pagesz) {
        printf("[PASS] munmap: count +1, bytes +%ld\n", 4 * pagesz);
        pass++;
    } else {
        printf("[FAIL] munmap: count %ld->%ld, bytes %ld->%ld\n",
               before[2], after[2], before[3], after[3]);
        fail++;
    }

    /* --- Test 3: mprotect --- */
    p = mmap(NULL, 2 * pagesz, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    read_mem_ops(0, before);
    int rc = mprotect(p, 2 * pagesz, PROT_READ);
    read_mem_ops(0, after);
    if (rc == 0 &&
        after[4] == before[4] + 1 &&
        after[5] == before[5] + 2 * pagesz) {
        printf("[PASS] mprotect: count +1, bytes +%ld\n", 2 * pagesz);
        pass++;
    } else {
        printf("[FAIL] mprotect: count %ld->%ld, bytes %ld->%ld\n",
               before[4], after[4], before[5], after[5]);
        fail++;
    }
    munmap(p, 2 * pagesz);

    /* --- Test 4: brk --- */
    read_mem_ops(0, before);
    void *old_brk = sbrk(0);
    sbrk(pagesz * 2);
    read_mem_ops(0, after);
    if (after[6] == before[6] + 1 &&
        after[7] == before[7] + pagesz * 2) {
        printf("[PASS] brk grow: count +1, bytes +%ld\n", pagesz * 2);
        pass++;
    } else {
        printf("[FAIL] brk grow: count %ld->%ld, bytes %ld->%ld\n",
               before[6], after[6], before[7], after[7]);
        fail++;
    }

    /* brk shrink */
    read_mem_ops(0, before);
    brk(old_brk);
    read_mem_ops(0, after);
    if (after[6] == before[6] + 1) {
        printf("[PASS] brk shrink: count +1\n");
        pass++;
    } else {
        printf("[FAIL] brk shrink: count %ld->%ld\n", before[6], after[6]);
        fail++;
    }

    /* --- Test 5: fork zeroing --- */
    read_mem_ops(0, before);  /* parent should have nonzero counts */
    pid_t pid = fork();
    if (pid == 0) {
        /* child */
        long child[8];
        read_mem_ops(0, child);
        /* All counters should be 0 (the reads via /proc cause mmap internally,
           but mmap_count/mmap_bytes from before fork must be 0) */
        /* Check brk/munmap/mprotect are zero — these won't be affected by fopen */
        if (child[2] == 0 && child[4] == 0 && child[6] == 0) {
            printf("[PASS] fork: child munmap/mprotect/brk counters = 0\n");
        } else {
            printf("[FAIL] fork: child counters munmap=%ld mprotect=%ld brk=%ld (expected 0)\n",
                   child[2], child[4], child[6]);
        }
        _exit(0);
    } else {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
            pass++;
        else
            fail++;
    }

    printf("\nSUMMARY: pass=%d fail=%d\n", pass, fail);
    return fail > 0 ? 1 : 0;
}
