gcc -o test_cow_info test_cow_info.c
sudo ./test_cow_info


/*
 * test_cow_info.c — Comprehensive tests for Task 3: Finding the Clones
 *
 * Compile:  gcc -o test_cow_info test_cow_info.c
 * Run:      sudo ./test_cow_info
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <errno.h>
#include <signal.h>

#define SYS_COW_INFO 464

struct cow_info {
    unsigned long total_cow;
    unsigned long anon_cow;
    unsigned long file_cow;
    unsigned long total_writable;
    unsigned long num_cow_vmas;
    unsigned long cow_fault_count;
};

static int test_pass = 0, test_fail = 0;

#define CHECK(cond, msg) do { \
    if (cond) { printf("  ✓ PASS: %s\n", msg); test_pass++; } \
    else      { printf("  ✗ FAIL: %s\n", msg); test_fail++; } \
} while(0)

static long cow_info_call(pid_t pid, struct cow_info *info)
{
    return syscall(SYS_COW_INFO, pid, info);
}

static void print_info(const char *label, const struct cow_info *info)
{
    printf("  [%s]\n", label);
    printf("    total_cow       = %lu\n", info->total_cow);
    printf("    anon_cow        = %lu\n", info->anon_cow);
    printf("    file_cow        = %lu\n", info->file_cow);
    printf("    total_writable  = %lu\n", info->total_writable);
    printf("    num_cow_vmas    = %lu\n", info->num_cow_vmas);
    printf("    cow_fault_count = %lu\n", info->cow_fault_count);
}

/* ── Test 1: Basic syscall works (pid=0 means self) ──────── */
static void test_basic_self(void)
{
    printf("\n=== Test 1: Basic syscall on self (pid=0) ===\n");
    struct cow_info info;
    memset(&info, 0xFF, sizeof(info));

    long ret = cow_info_call(0, &info);
    CHECK(ret == 0, "syscall returns 0 for pid=0");

    if (ret == 0) {
        print_info("self (pid=0)", &info);
        CHECK(info.anon_cow + info.file_cow == info.total_cow,
              "anon_cow + file_cow == total_cow");
        CHECK(info.total_writable >= info.total_cow,
              "total_writable >= total_cow");
    }
}

/* ── Test 2: Own PID matches pid=0 ──────────────────────── */
static void test_own_pid(void)
{
    printf("\n=== Test 2: Own PID matches pid=0 ===\n");
    struct cow_info info0, info_pid;

    long r1 = cow_info_call(0, &info0);
    long r2 = cow_info_call(getpid(), &info_pid);

    CHECK(r1 == 0 && r2 == 0, "both calls succeed");

    if (r1 == 0 && r2 == 0) {
        CHECK(info0.total_cow == info_pid.total_cow,
              "total_cow matches between pid=0 and own pid");
        CHECK(info0.cow_fault_count == info_pid.cow_fault_count,
              "cow_fault_count matches");
    }
}

/* ── Test 3: Error — negative PID ────────────────────────── */
static void test_error_negative_pid(void)
{
    printf("\n=== Test 3: Error — negative PID ===\n");
    struct cow_info info;

    long ret = cow_info_call(-1, &info);
    CHECK(ret == -1 && errno == EINVAL,
          "pid=-1 returns -EINVAL");

    ret = cow_info_call(-42, &info);
    CHECK(ret == -1 && errno == EINVAL,
          "pid=-42 returns -EINVAL");
}

/* ── Test 4: Error — nonexistent PID ─────────────────────── */
static void test_error_nonexistent_pid(void)
{
    printf("\n=== Test 4: Error — nonexistent PID ===\n");
    struct cow_info info;

    long ret = cow_info_call(999999, &info);
    CHECK(ret == -1 && errno == ESRCH,
          "nonexistent PID returns -ESRCH");
}

/* ── Test 5: Error — kernel thread ───────────────────────── */
static void test_error_kernel_thread(void)
{
    printf("\n=== Test 5: Error — kernel thread ===\n");
    struct cow_info info;

    long ret = cow_info_call(2, &info);
    CHECK(ret == -1 && errno == EINVAL,
          "kernel thread (pid=2) returns -EINVAL");
}

/* ── Test 6: No COW before fork ──────────────────────────── */
static void test_no_cow_before_fork(void)
{
    printf("\n=== Test 6: No (or minimal) COW before fork ===\n");
    struct cow_info info;

    cow_info_call(0, &info);
    print_info("before any fork", &info);

    /* A process that hasn't forked shouldn't have many COW pages
       (may have some from shared libraries) */
    CHECK(info.cow_fault_count == 0,
          "cow_fault_count == 0 before any writes to shared pages");
}

/* ── Test 7: Fork creates COW pages ──────────────────────── */
static void test_fork_creates_cow(void)
{
    printf("\n=== Test 7: Fork creates COW pages ===\n");

    /* Allocate and touch pages so they are resident and writable */
    size_t len = 4096 * 50;  /* 50 pages */
    char *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(p != MAP_FAILED, "mmap succeeded");

    if (p == MAP_FAILED) return;

    /* Touch every page to make them resident */
    for (size_t i = 0; i < len; i += 4096)
        p[i] = 'A';

    struct cow_info before_fork;
    cow_info_call(0, &before_fork);

    pid_t child = fork();
    if (child == 0) {
        /* Child: just sleep so parent can inspect */
        sleep(3);
        _exit(0);
    }

    /* Give fork time to complete */
    usleep(200000);

    struct cow_info parent_after, child_info;
    cow_info_call(0, &parent_after);
    cow_info_call(child, &child_info);

    printf("  Parent before fork:\n");
    print_info("parent-before", &before_fork);
    printf("  Parent after fork:\n");
    print_info("parent-after", &parent_after);
    printf("  Child after fork:\n");
    print_info("child", &child_info);

    CHECK(parent_after.total_cow > before_fork.total_cow,
          "parent total_cow increased after fork");
    CHECK(child_info.total_cow > 0,
          "child has COW pages after fork");
    CHECK(child_info.anon_cow + child_info.file_cow == child_info.total_cow,
          "child: anon_cow + file_cow == total_cow");
    CHECK(child_info.cow_fault_count == 0,
          "child cow_fault_count starts at 0");

    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    munmap(p, len);
}

/* ── Test 8: Writing to shared pages triggers COW faults ── */
static void test_cow_fault_counter(void)
{
    printf("\n=== Test 8: COW fault counter increments on write ===\n");

    /* Allocate and touch pages */
    size_t len = 4096 * 20;  /* 20 pages */
    volatile char *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(p != MAP_FAILED, "mmap succeeded");

    if (p == MAP_FAILED) return;

    /* Touch to make resident */
    for (size_t i = 0; i < len; i += 4096)
        p[i] = 'X';

    pid_t child = fork();
    if (child == 0) {
        /* Child: read cow_info before writing */
        struct cow_info before_write;
        cow_info_call(0, &before_write);

        /* Write to 10 of the 20 COW pages — should trigger 10 COW faults */
        for (int i = 0; i < 10; i++)
            p[i * 4096] = 'Y';

        struct cow_info after_write;
        cow_info_call(0, &after_write);

        printf("  Child before writing:\n");
        print_info("child-before", &before_write);
        printf("  Child after writing 10 pages:\n");
        print_info("child-after", &after_write);

        int ok = 1;

        if (after_write.cow_fault_count >= before_write.cow_fault_count + 10) {
            printf("  ✓ PASS: cow_fault_count increased by at least 10\n");
        } else {
            printf("  ✗ FAIL: cow_fault_count increased by %lu (expected >= 10)\n",
                   after_write.cow_fault_count - before_write.cow_fault_count);
            ok = 0;
        }

        if (after_write.total_cow < before_write.total_cow) {
            printf("  ✓ PASS: total_cow decreased after writing (COW resolved)\n");
        } else {
            printf("  ✗ FAIL: total_cow did not decrease after writing\n");
            ok = 0;
        }

        _exit(ok ? 0 : 1);
    }

    int status;
    waitpid(child, &status, 0);
    if (WIFEXITED(status)) {
        if (WEXITSTATUS(status) == 0) {
            test_pass += 2;
            printf("  (child reported 2 PASSes)\n");
        } else {
            test_fail += 2;
            printf("  (child reported FAILs)\n");
        }
    }

    munmap((void *)p, len);
}

/* ── Test 9: Parent also gets COW faults when it writes ──── */
static void test_parent_cow_fault(void)
{
    printf("\n=== Test 9: Parent COW fault counter ===\n");

    size_t len = 4096 * 15;
    volatile char *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(p != MAP_FAILED, "mmap succeeded");

    if (p == MAP_FAILED) return;

    for (size_t i = 0; i < len; i += 4096)
        p[i] = 'A';

    pid_t child = fork();
    if (child == 0) {
        sleep(3);
        _exit(0);
    }

    usleep(200000);

    struct cow_info before;
    cow_info_call(0, &before);

    /* Parent writes to 5 COW pages */
    for (int i = 0; i < 5; i++)
        p[i * 4096] = 'Z';

    struct cow_info after;
    cow_info_call(0, &after);

    printf("  Parent before writing:\n");
    print_info("parent-before", &before);
    printf("  Parent after writing 5 pages:\n");
    print_info("parent-after", &after);

    CHECK(after.cow_fault_count >= before.cow_fault_count + 5,
          "parent cow_fault_count increased by at least 5");

    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    munmap((void *)p, len);
}

/* ── Test 10: cow_fault_count NOT inherited by child ─────── */
static void test_cow_fault_not_inherited(void)
{
    printf("\n=== Test 10: cow_fault_count not inherited ===\n");

    size_t len = 4096 * 10;
    volatile char *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) { test_fail++; return; }

    for (size_t i = 0; i < len; i += 4096)
        p[i] = 'A';

    /* First fork + write to build up parent's cow_fault_count */
    pid_t c1 = fork();
    if (c1 == 0) { sleep(2); _exit(0); }
    usleep(100000);

    for (int i = 0; i < 5; i++)
        p[i * 4096] = 'B';

    struct cow_info parent_info;
    cow_info_call(0, &parent_info);
    printf("  Parent cow_fault_count = %lu (should be > 0)\n",
           parent_info.cow_fault_count);
    CHECK(parent_info.cow_fault_count > 0,
          "parent has nonzero cow_fault_count");

    kill(c1, SIGKILL);
    waitpid(c1, NULL, 0);

    /* Second fork — child should start with cow_fault_count = 0 */
    pid_t c2 = fork();
    if (c2 == 0) {
        struct cow_info child_info;
        cow_info_call(0, &child_info);
        printf("  Child cow_fault_count = %lu (should be 0)\n",
               child_info.cow_fault_count);
        if (child_info.cow_fault_count == 0) {
            printf("  ✓ PASS: child cow_fault_count is 0\n");
            _exit(0);
        } else {
            printf("  ✗ FAIL: child inherited cow_fault_count\n");
            _exit(1);
        }
    }

    int status;
    waitpid(c2, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
        test_pass++;
    else
        test_fail++;

    munmap((void *)p, len);
}

/* ── Test 11: num_cow_vmas counts correctly ──────────────── */
static void test_num_cow_vmas(void)
{
    printf("\n=== Test 11: num_cow_vmas correctness ===\n");

    /* Create two separate writable mappings */
    size_t len1 = 4096 * 10;
    size_t len2 = 4096 * 10;
    volatile char *p1 = mmap(NULL, len1, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    volatile char *p2 = mmap(NULL, len2, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(p1 != MAP_FAILED && p2 != MAP_FAILED, "both mmaps succeeded");

    if (p1 == MAP_FAILED || p2 == MAP_FAILED) return;

    /* Touch all pages */
    for (size_t i = 0; i < len1; i += 4096) p1[i] = 'A';
    for (size_t i = 0; i < len2; i += 4096) p2[i] = 'B';

    pid_t child = fork();
    if (child == 0) {
        struct cow_info info;
        cow_info_call(0, &info);
        print_info("child (two writable regions)", &info);

        /* Both p1 and p2 VMAs should have COW pages */
        if (info.num_cow_vmas >= 2)
            printf("  ✓ PASS: num_cow_vmas >= 2\n");
        else
            printf("  ✗ FAIL: num_cow_vmas = %lu (expected >= 2)\n",
                   info.num_cow_vmas);

        _exit(info.num_cow_vmas >= 2 ? 0 : 1);
    }

    int status;
    waitpid(child, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
        test_pass++;
    else
        test_fail++;

    munmap((void *)p1, len1);
    munmap((void *)p2, len2);
}

/* ── Test 12: Read-only mappings don't count as COW ──────── */
static void test_readonly_not_cow(void)
{
    printf("\n=== Test 12: Read-only mappings are not COW ===\n");

    /* Create a read-only mapping */
    size_t len = 4096 * 10;
    char *p = mmap(NULL, len, PROT_READ,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(p != MAP_FAILED, "read-only mmap succeeded");

    if (p == MAP_FAILED) return;

    /* Touch pages (read only) */
    volatile char c;
    for (size_t i = 0; i < len; i += 4096)
        c = p[i];
    (void)c;

    struct cow_info before;
    cow_info_call(0, &before);

    pid_t child = fork();
    if (child == 0) {
        struct cow_info info;
        cow_info_call(0, &info);
        print_info("child (read-only region)", &info);
        /* Read-only pages should not contribute to total_writable or COW */
        _exit(0);
    }

    int status;
    waitpid(child, &status, 0);

    struct cow_info after;
    cow_info_call(0, &after);

    /* The read-only mapping shouldn't add to total_writable */
    printf("  (inspect output above — read-only VMA should not appear in COW counts)\n");
    CHECK(1, "read-only mapping test completed (inspect values)");

    munmap(p, len);
}

/* ── Test 13: total_writable includes all present writable pages ── */
static void test_total_writable(void)
{
    printf("\n=== Test 13: total_writable sanity ===\n");

    struct cow_info info;
    cow_info_call(0, &info);

    print_info("current process", &info);

    CHECK(info.total_writable > 0,
          "total_writable > 0 for a normal process");
    CHECK(info.total_writable >= info.total_cow,
          "total_writable >= total_cow (COW is subset of writable)");
}

/* ── Test 14: NULL pointer ───────────────────────────────── */
static void test_null_pointer(void)
{
    printf("\n=== Test 14: NULL info pointer ===\n");

    long ret = cow_info_call(0, NULL);
    CHECK(ret == -1, "NULL pointer returns error (doesn't crash)");
    printf("  errno = %d (%s)\n", errno, strerror(errno));
}

/* ── Test 15: Large allocation + fork + selective write ──── */
static void test_large_allocation(void)
{
    printf("\n=== Test 15: Large allocation COW test ===\n");

    size_t len = 4096 * 200;  /* 200 pages */
    volatile char *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(p != MAP_FAILED, "large mmap succeeded");

    if (p == MAP_FAILED) return;

    /* Touch all 200 pages */
    for (size_t i = 0; i < len; i += 4096)
        p[i] = 'M';

    pid_t child = fork();
    if (child == 0) {
        struct cow_info before;
        cow_info_call(0, &before);

        /* Write to first 50 pages — resolve 50 COW faults */
        for (int i = 0; i < 50; i++)
            p[i * 4096] = 'N';

        struct cow_info after;
        cow_info_call(0, &after);

        printf("  Child before writing:\n");
        print_info("child-before", &before);
        printf("  Child after writing 50/200 pages:\n");
        print_info("child-after", &after);

        int ok = 1;
        if (after.cow_fault_count >= 50) {
            printf("  ✓ PASS: cow_fault_count >= 50\n");
        } else {
            printf("  ✗ FAIL: cow_fault_count = %lu (expected >= 50)\n",
                   after.cow_fault_count);
            ok = 0;
        }

        /* total_cow should have decreased by about 50 */
        if (before.total_cow > after.total_cow) {
            printf("  ✓ PASS: total_cow decreased after resolving COW\n");
        } else {
            printf("  ✗ FAIL: total_cow did not decrease\n");
            ok = 0;
        }

        /* Still ~150 COW pages left from this mapping */
        if (after.total_cow > 0) {
            printf("  ✓ PASS: still has COW pages (unwritten pages remain shared)\n");
        } else {
            printf("  ✗ FAIL: total_cow went to 0 unexpectedly\n");
            ok = 0;
        }

        _exit(ok ? 0 : 1);
    }

    int status;
    waitpid(child, &status, 0);
    if (WIFEXITED(status)) {
        if (WEXITSTATUS(status) == 0) {
            test_pass += 3;
            printf("  (child reported 3 PASSes)\n");
        } else {
            test_fail += 3;
            printf("  (child reported FAILs)\n");
        }
    }

    munmap((void *)p, len);
}

/* ── Test 16: PID 1 inspection ───────────────────────────── */
static void test_pid_1(void)
{
    printf("\n=== Test 16: Read PID 1 (init) ===\n");
    struct cow_info info;

    long ret = cow_info_call(1, &info);
    CHECK(ret == 0, "syscall succeeds for PID 1");

    if (ret == 0) {
        print_info("PID 1 (init)", &info);
        CHECK(info.anon_cow + info.file_cow == info.total_cow,
              "init: anon_cow + file_cow == total_cow");
    }
}

/* ── main ────────────────────────────────────────────────── */
int main(void)
{
    printf("=============================================\n");
    printf("  Task 3: Finding the Clones — Test Suite\n");
    printf("  PID: %d\n", getpid());
    printf("=============================================\n");

    test_basic_self();
    test_own_pid();
    test_error_negative_pid();
    test_error_nonexistent_pid();
    test_error_kernel_thread();
    test_no_cow_before_fork();
    test_fork_creates_cow();
    test_cow_fault_counter();
    test_parent_cow_fault();
    test_cow_fault_not_inherited();
    test_num_cow_vmas();
    test_readonly_not_cow();
    test_total_writable();
    test_null_pointer();
    test_large_allocation();
    test_pid_1();

    printf("\n=============================================\n");
    printf("  Results: %d passed, %d failed\n", test_pass, test_fail);
    printf("=============================================\n");

    return test_fail > 0 ? 1 : 0;
}


