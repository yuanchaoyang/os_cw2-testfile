#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SYS_VA_SPACE_STAT
#define SYS_VA_SPACE_STAT 463
#endif

#define BUF_CAP (1024 * 1024)
#define RESIDENT_TOLERANCE 8UL

struct addr_space_info {
    unsigned long num_vmas;
    unsigned long num_anon;
    unsigned long num_file;
    unsigned long num_w_and_x;
    unsigned long total_mapped;
    unsigned long total_resident;
    unsigned long largest_gap;
    unsigned long stack_size;
    unsigned long heap_size;
};

struct test_state {
    int passed;
    int failed;
    int skipped;
};

static char bigbuf[BUF_CAP];
static long g_pagesz = 4096;

static long call_va_space_stat(pid_t pid, struct addr_space_info *info) {
    errno = 0;
    return syscall(SYS_VA_SPACE_STAT, pid, info);
}

static void record_result(struct test_state *ts, const char *name, bool ok,
                          bool skipped, const char *fmt, ...) {
    va_list ap;
    printf("[%s] %s", skipped ? "SKIP" : (ok ? "PASS" : "FAIL"), name);
    if (fmt && fmt[0]) {
        printf(" : ");
        va_start(ap, fmt);
        vprintf(fmt, ap);
        va_end(ap);
    }
    printf("\n");

    if (skipped) {
        ts->skipped++;
    } else if (ok) {
        ts->passed++;
    } else {
        ts->failed++;
    }
}

static ssize_t slurp_file(const char *path, char *buf, size_t cap) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    size_t off = 0;
    while (off + 1 < cap) {
        ssize_t n = read(fd, buf + off, cap - off - 1);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            return -1;
        }
        if (n == 0) {
            break;
        }
        off += (size_t)n;
    }
    close(fd);

    if (off + 1 >= cap) {
        errno = ENOMEM;
        return -1;
    }
    buf[off] = '\0';
    return (ssize_t)off;
}

static void trim_trailing(char *s) {
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' ' || s[n - 1] == '\t')) {
        s[--n] = '\0';
    }
}

static char *skip_spaces(char *s) {
    while (*s == ' ' || *s == '\t') {
        s++;
    }
    return s;
}

static int read_self_stat(unsigned long *start_stack, unsigned long *start_brk) {
    char statbuf[8192];
    if (slurp_file("/proc/self/stat", statbuf, sizeof(statbuf)) < 0) {
        return -1;
    }

    char *rp = strrchr(statbuf, ')');
    if (!rp || rp[1] != ' ') {
        errno = EINVAL;
        return -1;
    }

    char *fields = rp + 2; /* field 3 starts here */
    char *save = NULL;
    char *tok = strtok_r(fields, " ", &save);
    int idx = 0; /* idx 0 == field 3 */
    unsigned long long stack_val = 0;
    unsigned long long brk_val = 0;
    bool have_stack = false;
    bool have_brk = false;

    while (tok) {
        if (idx == 25) { /* field 28: startstack */
            stack_val = strtoull(tok, NULL, 10);
            have_stack = true;
        } else if (idx == 44) { /* field 47: start_brk */
            brk_val = strtoull(tok, NULL, 10);
            have_brk = true;
            break;
        }
        tok = strtok_r(NULL, " ", &save);
        idx++;
    }

    if (!have_stack || !have_brk) {
        errno = EINVAL;
        return -1;
    }

    *start_stack = (unsigned long)stack_val;
    *start_brk = (unsigned long)brk_val;
    return 0;
}

static int parse_maps_oracle(char *maps_buf, unsigned long start_stack,
                             struct addr_space_info *out) {
    memset(out, 0, sizeof(*out));

    unsigned long prev_end = 0;
    bool first = true;

    char *save = NULL;
    for (char *line = strtok_r(maps_buf, "\n", &save);
         line != NULL;
         line = strtok_r(NULL, "\n", &save)) {
        unsigned long start = 0, end = 0, offset = 0, inode = 0;
        char perms[5] = {0};
        char dev[32] = {0};
        int consumed = 0;

        int rc = sscanf(line, "%lx-%lx %4s %lx %31s %lu %n",
                        &start, &end, perms, &offset, dev, &inode, &consumed);
        if (rc < 6) {
            continue;
        }

        char *path = skip_spaces(line + consumed);
        trim_trailing(path);

        /* [vsyscall] is a special x86-64 compat entry above TASK_SIZE;
         * it is not a real VMA in mm_struct so the kernel syscall does
         * not count it.  Skip it here to keep the oracle consistent. */
        if (strcmp(path, "[vsyscall]") == 0)
            continue;

        out->num_vmas++;
        out->total_mapped += (end - start);

        if (!first && start >= prev_end) {
            unsigned long gap = start - prev_end;
            if (gap > out->largest_gap) {
                out->largest_gap = gap;
            }
        }
        first = false;
        prev_end = end;

        if (start <= start_stack && start_stack < end) {
            out->stack_size = end - start;
        }

        if (perms[1] == 'w' && perms[2] == 'x') {
            out->num_w_and_x++;
        }

        if (path[0] == '\0' || path[0] == '[') {
            out->num_anon++;
        } else {
            out->num_file++;
        }
    }

    return 0;
}

static int parse_smaps_rollup_rss(unsigned long *rss_pages) {
    char buf[65536];
    if (slurp_file("/proc/self/smaps_rollup", buf, sizeof(buf)) < 0) {
        return -1;
    }

    char *save = NULL;
    for (char *line = strtok_r(buf, "\n", &save);
         line != NULL;
         line = strtok_r(NULL, "\n", &save)) {
        unsigned long rss_kb = 0;
        if (sscanf(line, "Rss: %lu kB", &rss_kb) == 1) {
            *rss_pages = (rss_kb * 1024UL) / (unsigned long)g_pagesz;
            return 0;
        }
    }

    errno = EINVAL;
    return -1;
}

static int read_self_oracle(struct addr_space_info *out) {
    unsigned long start_stack = 0, start_brk = 0, rss_pages = 0;
    if (read_self_stat(&start_stack, &start_brk) < 0) {
        return -1;
    }
    if (slurp_file("/proc/self/maps", bigbuf, sizeof(bigbuf)) < 0) {
        return -1;
    }

    if (parse_maps_oracle(bigbuf, start_stack, out) < 0) {
        return -1;
    }
    if (parse_smaps_rollup_rss(&rss_pages) < 0) {
        return -1;
    }

    out->total_resident = rss_pages;
    unsigned long cur_brk = (unsigned long)sbrk(0);
    out->heap_size = cur_brk - start_brk;
    return 0;
}

static bool compare_to_oracle(const struct addr_space_info *got,
                              const struct addr_space_info *want,
                              char *why, size_t why_sz) {
    if (got->num_vmas != want->num_vmas) {
        snprintf(why, why_sz, "num_vmas got=%lu want=%lu", got->num_vmas, want->num_vmas);
        return false;
    }
    if (got->num_anon != want->num_anon) {
        snprintf(why, why_sz, "num_anon got=%lu want=%lu", got->num_anon, want->num_anon);
        return false;
    }
    if (got->num_file != want->num_file) {
        snprintf(why, why_sz, "num_file got=%lu want=%lu", got->num_file, want->num_file);
        return false;
    }
    if (got->num_w_and_x != want->num_w_and_x) {
        snprintf(why, why_sz, "num_w_and_x got=%lu want=%lu", got->num_w_and_x, want->num_w_and_x);
        return false;
    }
    if (got->total_mapped != want->total_mapped) {
        snprintf(why, why_sz, "total_mapped got=%lu want=%lu", got->total_mapped, want->total_mapped);
        return false;
    }
    if (got->largest_gap != want->largest_gap) {
        snprintf(why, why_sz, "largest_gap got=%lu want=%lu", got->largest_gap, want->largest_gap);
        return false;
    }
    if (got->stack_size != want->stack_size) {
        snprintf(why, why_sz, "stack_size got=%lu want=%lu", got->stack_size, want->stack_size);
        return false;
    }
    if (got->heap_size != want->heap_size) {
        snprintf(why, why_sz, "heap_size got=%lu want=%lu", got->heap_size, want->heap_size);
        return false;
    }
    unsigned long diff = (got->total_resident > want->total_resident)
                           ? (got->total_resident - want->total_resident)
                           : (want->total_resident - got->total_resident);
    if (diff > RESIDENT_TOLERANCE) {
        snprintf(why, why_sz, "total_resident got=%lu want=%lu diff=%lu",
                 got->total_resident, want->total_resident, diff);
        return false;
    }
    if (got->num_anon + got->num_file != got->num_vmas) {
        snprintf(why, why_sz, "invariant fail: anon(%lu)+file(%lu)!=vmas(%lu)",
                 got->num_anon, got->num_file, got->num_vmas);
        return false;
    }
    why[0] = '\0';
    return true;
}

static int pipe_write_full(int fd, const void *buf, size_t len) {
    const char *p = (const char *)buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

static int pipe_read_full(int fd, void *buf, size_t len) {
    char *p = (char *)buf;
    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            errno = EPIPE;
            return -1;
        }
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

static pid_t find_nonexistent_pid(void) {
    char path[64];
    for (pid_t p = 500000; p < 500200; p++) {
        snprintf(path, sizeof(path), "/proc/%d/stat", (int)p);
        if (access(path, F_OK) != 0 && errno == ENOENT) {
            return p;
        }
    }
    return (pid_t)123456789;
}

static bool probe_pid2_is_kthreadd(void) {
    char buf[128];
    if (slurp_file("/proc/2/comm", buf, sizeof(buf)) < 0) {
        return false;
    }
    trim_trailing(buf);
    return strcmp(buf, "kthreadd") == 0;
}

static void warm_up(void) {
    struct addr_space_info a, b;
    (void)call_va_space_stat(0, &a);
    (void)read_self_oracle(&b);
}

static void test_error_paths(struct test_state *ts) {
    struct addr_space_info info;
    long ret;
    bool ok;

    ret = call_va_space_stat(-1, &info);
    ok = (ret == -1 && errno == EINVAL);
    record_result(ts, "negative pid -> EINVAL", ok, false,
                  "ret=%ld errno=%d", ret, errno);

    pid_t bad = find_nonexistent_pid();
    ret = call_va_space_stat(bad, &info);
    ok = (ret == -1 && errno == ESRCH);
    record_result(ts, "nonexistent pid -> ESRCH", ok, false,
                  "pid=%d ret=%ld errno=%d", (int)bad, ret, errno);

    if (probe_pid2_is_kthreadd()) {
        ret = call_va_space_stat(2, &info);
        ok = (ret == -1 && errno == EINVAL);
        record_result(ts, "kernel thread without mm -> EINVAL", ok, false,
                      "ret=%ld errno=%d", ret, errno);
    } else {
        record_result(ts, "kernel thread without mm -> EINVAL", false, true,
                      "pid 2 is not kthreadd in this environment");
    }
}

static void test_pid0_equals_self(struct test_state *ts) {
    struct addr_space_info a, b;
    char why[256];
    long r1 = call_va_space_stat(0, &a);
    long r2 = call_va_space_stat(getpid(), &b);
    /* Use tolerance comparison: total_resident is a point-in-time snapshot
     * and can differ by a few pages between two sequential calls. */
    bool ok = (r1 == 0 && r2 == 0 && compare_to_oracle(&a, &b, why, sizeof(why)));
    record_result(ts, "pid=0 equals pid=getpid()", ok, false,
                  "%s", (r1 != 0 || r2 != 0) ? "syscall failed" : (ok ? "matched" : why));
}

static void test_baseline_vs_oracle(struct test_state *ts) {
    struct addr_space_info got, want;
    char why[256];
    long ret = call_va_space_stat(0, &got);
    bool ok = false;

    if (ret == 0 && read_self_oracle(&want) == 0) {
        ok = compare_to_oracle(&got, &want, why, sizeof(why));
        record_result(ts, "baseline exact fields vs /proc oracle", ok, false,
                      "%s", ok ? "matched" : why);
    } else {
        record_result(ts, "baseline exact fields vs /proc oracle", false, false,
                      "ret=%ld errno=%d", ret, errno);
    }
}

static void test_rwx_mapping_vs_oracle(struct test_state *ts) {
    struct addr_space_info got, want;
    char why[256];
    void *p = mmap(NULL, (size_t)g_pagesz,
                   PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        record_result(ts, "RWX anonymous mapping counted in num_w_and_x", false, true,
                      "mmap failed errno=%d", errno);
        return;
    }

    memset(p, 0xAB, (size_t)g_pagesz);
    long ret = call_va_space_stat(0, &got);
    bool ok = false;
    if (ret == 0 && read_self_oracle(&want) == 0) {
        ok = compare_to_oracle(&got, &want, why, sizeof(why));
        record_result(ts, "RWX anonymous mapping counted in num_w_and_x", ok, false,
                      "%s", ok ? "matched" : why);
    } else {
        record_result(ts, "RWX anonymous mapping counted in num_w_and_x", false, false,
                      "ret=%ld errno=%d", ret, errno);
    }

    munmap(p, (size_t)g_pagesz);
}

static void test_file_mapping_vs_oracle(struct test_state *ts) {
    struct addr_space_info got, want;
    char why[256];
    char tmpl[] = "/tmp/task2_fileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) {
        record_result(ts, "file-backed mapping counted in num_file", false, false,
                      "mkstemp errno=%d", errno);
        return;
    }
    unlink(tmpl);

    size_t len = (size_t)(2 * g_pagesz);
    if (ftruncate(fd, (off_t)len) != 0) {
        record_result(ts, "file-backed mapping counted in num_file", false, false,
                      "ftruncate errno=%d", errno);
        close(fd);
        return;
    }

    void *p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (p == MAP_FAILED) {
        record_result(ts, "file-backed mapping counted in num_file", false, false,
                      "mmap errno=%d", errno);
        close(fd);
        return;
    }
    memset(p, 0x5A, len);

    long ret = call_va_space_stat(0, &got);
    bool ok = false;
    if (ret == 0 && read_self_oracle(&want) == 0) {
        ok = compare_to_oracle(&got, &want, why, sizeof(why));
        record_result(ts, "file-backed mapping counted in num_file", ok, false,
                      "%s", ok ? "matched" : why);
    } else {
        record_result(ts, "file-backed mapping counted in num_file", false, false,
                      "ret=%ld errno=%d", ret, errno);
    }

    munmap(p, len);
    close(fd);
}

static void test_heap_delta(struct test_state *ts) {
    struct addr_space_info a, b, c;
    long ret1 = call_va_space_stat(0, &a);
    if (ret1 != 0) {
        record_result(ts, "heap_size tracks brk growth/shrink", false, false,
                      "initial syscall failed errno=%d", errno);
        return;
    }

    intptr_t inc = (intptr_t)(2 * g_pagesz);
    void *old = sbrk(0);
    if (sbrk(inc) == (void *)-1) {
        record_result(ts, "heap_size tracks brk growth/shrink", false, false,
                      "sbrk(+%ld) failed errno=%d", (long)inc, errno);
        return;
    }

    long ret2 = call_va_space_stat(0, &b);
    bool grow_ok = (ret2 == 0 && b.heap_size == a.heap_size + (unsigned long)inc);

    bool shrink_ok = false;
    if (brk(old) == 0) {
        long ret3 = call_va_space_stat(0, &c);
        shrink_ok = (ret3 == 0 && c.heap_size == a.heap_size);
    }

    record_result(ts, "heap_size tracks brk growth/shrink",
                  grow_ok && shrink_ok, false,
                  "before=%lu after_grow=%lu back=%lu",
                  a.heap_size, b.heap_size, c.heap_size);
}

static void test_resident_delta(struct test_state *ts) {
    const size_t pages = 64;
    const size_t len = pages * (size_t)g_pagesz;
    struct addr_space_info before_touch = {0}, after_touch = {0}, after_drop = {0};

    void *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        record_result(ts, "total_resident responds to page faults and MADV_DONTNEED",
                      false, false, "mmap failed errno=%d", errno);
        return;
    }

    long r0 = call_va_space_stat(0, &before_touch);
    volatile unsigned char *vp = (volatile unsigned char *)p;
    for (size_t i = 0; i < pages; i++) {
        vp[i * (size_t)g_pagesz] = (unsigned char)i;
    }
    long r1 = call_va_space_stat(0, &after_touch);

    bool rise_ok = false;
    if (r0 == 0 && r1 == 0 && after_touch.total_resident >= before_touch.total_resident) {
        unsigned long delta = after_touch.total_resident - before_touch.total_resident;
        rise_ok = (delta + 4 >= pages);
    }

    bool drop_ok = false;
    if (madvise(p, len, MADV_DONTNEED) == 0) {
        long r2 = call_va_space_stat(0, &after_drop);
        if (r2 == 0 && after_touch.total_resident >= after_drop.total_resident) {
            unsigned long delta = after_touch.total_resident - after_drop.total_resident;
            drop_ok = (delta + 4 >= pages);
        }
    }

    record_result(ts, "total_resident responds to page faults and MADV_DONTNEED",
                  rise_ok && drop_ok, false,
                  "before=%lu after_touch=%lu after_drop=%lu",
                  before_touch.total_resident,
                  after_touch.total_resident,
                  after_drop.total_resident);

    munmap(p, len);
}

static void child_setup_and_report(int ready_fd, int done_fd) {
    struct addr_space_info info;
    char tmpl[] = "/tmp/task2_childXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd >= 0) {
        unlink(tmpl);
        (void)ftruncate(fd, (off_t)g_pagesz);
    }

    void *anon = mmap(NULL, (size_t)(8 * g_pagesz), PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (anon != MAP_FAILED) {
        memset(anon, 0x11, (size_t)(8 * g_pagesz));
    }

    void *rwx = mmap(NULL, (size_t)g_pagesz,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (rwx != MAP_FAILED) {
        memset(rwx, 0x22, (size_t)g_pagesz);
    }

    void *filemap = MAP_FAILED;
    if (fd >= 0) {
        filemap = mmap(NULL, (size_t)g_pagesz, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
        if (filemap != MAP_FAILED) {
            memset(filemap, 0x33, (size_t)g_pagesz);
        }
    }

    if (call_va_space_stat(0, &info) != 0) {
        memset(&info, 0, sizeof(info));
        info.num_vmas = ULONG_MAX;
    }

    (void)pipe_write_full(ready_fd, &info, sizeof(info));
    char dummy;
    (void)pipe_read_full(done_fd, &dummy, 1);

    if (filemap != MAP_FAILED) munmap(filemap, (size_t)g_pagesz);
    if (rwx != MAP_FAILED) munmap(rwx, (size_t)g_pagesz);
    if (anon != MAP_FAILED) munmap(anon, (size_t)(8 * g_pagesz));
    if (fd >= 0) close(fd);
    _exit(0);
}

static void test_cross_pid_child(struct test_state *ts) {
    int p2c[2] = {-1, -1};
    int c2p[2] = {-1, -1};
    if (pipe(p2c) != 0 || pipe(c2p) != 0) {
        record_result(ts, "query another process by pid", false, false,
                      "pipe failed errno=%d", errno);
        return;
    }

    pid_t pid = fork();
    if (pid < 0) {
        record_result(ts, "query another process by pid", false, false,
                      "fork failed errno=%d", errno);
        return;
    }

    if (pid == 0) {
        close(p2c[1]);
        close(c2p[0]);
        child_setup_and_report(c2p[1], p2c[0]);
    }

    close(p2c[0]);
    close(c2p[1]);

    struct addr_space_info child_self = {0}, parent_view = {0};
    bool ok = false;

    if (pipe_read_full(c2p[0], &child_self, sizeof(child_self)) == 0) {
        long ret = call_va_space_stat(pid, &parent_view);
        char why[256];
        /* Use tolerance comparison: total_resident can change between the
         * child's self-measurement and the parent's cross-pid query due to
         * kernel page reclaim while the child is blocked on the pipe. */
        ok = (ret == 0 && child_self.num_vmas != ULONG_MAX &&
              compare_to_oracle(&parent_view, &child_self, why, sizeof(why)));
        record_result(ts, "query another process by pid", ok, false,
                      "%s (child_vmas=%lu parent_vmas=%lu)",
                      ok ? "matched" : why,
                      child_self.num_vmas, parent_view.num_vmas);
    } else {
        record_result(ts, "query another process by pid", false, false,
                      "failed to read child report errno=%d", errno);
    }

    char done = 'X';
    (void)pipe_write_full(p2c[1], &done, 1);
    close(p2c[1]);
    close(c2p[0]);
    (void)waitpid(pid, NULL, 0);
}

int main(void) {
    g_pagesz = sysconf(_SC_PAGESIZE);
    if (g_pagesz <= 0) {
        g_pagesz = 4096;
    }

    printf("Task 2 stronger tester for syscall 463 (va_space_stat)\n");
    printf("page_size=%ld\n", g_pagesz);

    struct addr_space_info probe = {0};
    long probe_ret = call_va_space_stat(0, &probe);
    if (probe_ret == -1 && errno == ENOSYS) {
        printf("syscall 463 is not implemented in this kernel (ENOSYS)\n");
        return 2;
    }

    warm_up();

    struct test_state ts = {0, 0, 0};
    test_error_paths(&ts);
    test_pid0_equals_self(&ts);
    test_baseline_vs_oracle(&ts);
    test_rwx_mapping_vs_oracle(&ts);
    test_file_mapping_vs_oracle(&ts);
    test_heap_delta(&ts);
    test_resident_delta(&ts);
    test_cross_pid_child(&ts);

    printf("\nSUMMARY: pass=%d fail=%d skip=%d\n", ts.passed, ts.failed, ts.skipped);
    if (ts.failed == 0) {
        printf("OVERALL PASS\n");
        return 0;
    }

    printf("OVERALL FAIL\n");
    return 1;
}

