/*
 * monitor.c — per-user CPU usage monitor
 *
 * Usage: ./monitor.exe <seconds>
 *
 * Samples /proc every second, aggregates CPU time (utime+stime) per user,
 * and prints a ranked summary at the end.  Only CPU time accumulated since
 * monitor.exe started is counted.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pwd.h>
#include <ctype.h>

/* PIDs on Linux are < 4194304, but the default pid_max is 32768.
 * 65536 covers the common cases without using too much memory (~1 MB). */
#define PID_MAX   65536
#define MAX_USERS 4096

/* Per-PID state kept between samples. */
typedef struct {
    int       active;        /* 1 once we have seen this PID at least once */
    uid_t     uid;           /* owner recorded on first sight               */
    long long prev_jiffies;  /* utime+stime at the last sample              */
} PidSlot;

/* Per-user accumulator. */
typedef struct {
    uid_t     uid;
    long long cpu_ms;
    char      name[64];
} UserEntry;

static PidSlot   pid_slots[PID_MAX];
static UserEntry user_table[MAX_USERS];
static int       user_count;
static long      hz;   /* clock ticks per second from sysconf(_SC_CLK_TCK) */

/* -------------------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------------- */

static UserEntry *find_user(uid_t uid)
{
    int i;
    for (i = 0; i < user_count; i++)
        if (user_table[i].uid == uid)
            return &user_table[i];

    if (user_count >= MAX_USERS)
        return NULL;

    UserEntry *u = &user_table[user_count++];
    u->uid    = uid;
    u->cpu_ms = 0;

    struct passwd *pw = getpwuid(uid);
    if (pw)
        snprintf(u->name, sizeof(u->name), "%s", pw->pw_name);
    else
        snprintf(u->name, sizeof(u->name), "%u", (unsigned)uid);

    return u;
}

/*
 * Read utime+stime (in jiffies) from /proc/<pid>/stat.
 * Returns -1 on any error (process may have exited).
 *
 * /proc/<pid>/stat layout (man 5 proc_pid_stat, fields 1-indexed):
 *   1:pid 2:(comm) 3:state 4:ppid 5:pgrp 6:session 7:tty_nr 8:tpgid
 *   9:flags 10:minflt 11:cminflt 12:majflt 13:cmajflt 14:utime 15:stime …
 *
 * The comm field can contain spaces and parentheses, so we anchor on the
 * *last* ')' in the line.
 */
static long long read_proc_stat(int pid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);

    FILE *f = fopen(path, "r");
    if (!f)
        return -1;

    char buf[4096];
    int ok = (fgets(buf, sizeof(buf), f) != NULL);
    fclose(f);
    if (!ok)
        return -1;

    char *p = strrchr(buf, ')');
    if (!p)
        return -1;
    p++;  /* step past ')' */

    /*
     * Fields after ')':
     *   3:state  4:ppid  5:pgrp  6:session  7:tty_nr  8:tpgid
     *   9:flags  10:minflt  11:cminflt  12:majflt  13:cmajflt
     *   14:utime  15:stime
     *
     * Use strtoul-based walking to avoid %*lu sscanf warnings.
     */

    /* field 3: state (single char) */
    while (*p == ' ' || *p == '\t') p++;
    if (!*p) return -1;
    p++;  /* skip state character */

    /* fields 4–13: skip 10 numeric values */
    char *end;
    for (int i = 0; i < 10; i++) {
        strtol(p, &end, 10);
        if (end == p) return -1;
        p = end;
    }

    /* field 14: utime */
    unsigned long utime = strtoul(p, &end, 10);
    if (end == p) return -1;
    p = end;

    /* field 15: stime */
    unsigned long stime = strtoul(p, &end, 10);
    if (end == p) return -1;

    return (long long)(utime + stime);
}

/*
 * Get the real UID of a process by stat()-ing /proc/<pid>.
 * The owner of that directory is the real UID of the process.
 */
static uid_t read_proc_uid(int pid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d", pid);

    struct stat st;
    if (stat(path, &st) != 0)
        return (uid_t)-1;

    return st.st_uid;
}

/* -------------------------------------------------------------------------
 * Sampling logic
 * ---------------------------------------------------------------------- */

/*
 * Walk /proc and update per-user CPU accumulators.
 *
 * is_baseline == 1  →  first call; just record the current jiffies for
 *                       every existing process so future deltas exclude
 *                       CPU time spent before monitor.exe started.
 *
 * is_baseline == 0  →  regular sample; accumulate deltas since the
 *                       previous sample.  For a PID that appears for the
 *                       first time after the baseline, count all its CPU
 *                       time (it was born after monitor started).
 */
static void do_sample(int is_baseline)
{
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir)
        return;

    struct dirent *de;
    while ((de = readdir(proc_dir)) != NULL) {

        /* Only process all-digit directory names (PIDs). */
        const char *s = de->d_name;
        int pid = 0;
        int valid = 1;
        for (; *s; s++) {
            if (!isdigit((unsigned char)*s)) {
                valid = 0;
                break;
            }
            pid = pid * 10 + (*s - '0');
        }
        if (!valid || pid <= 0 || pid >= PID_MAX)
            continue;

        long long jiffies = read_proc_stat(pid);
        if (jiffies < 0)
            continue;   /* process exited between readdir and fopen */

        uid_t uid = read_proc_uid(pid);
        if (uid == (uid_t)-1)
            continue;

        PidSlot *slot = &pid_slots[pid];

        if (!slot->active || slot->uid != uid) {
            /*
             * PID seen for the first time (or PID was reused by a new
             * process with a different UID).
             */
            slot->active = 1;
            slot->uid    = uid;

            if (is_baseline) {
                /* Record current jiffies as baseline; don't count them. */
                slot->prev_jiffies = jiffies;
            } else {
                /*
                 * Process started after monitor.exe: count all its
                 * accumulated CPU time (it has no pre-monitor history).
                 */
                long long ms = jiffies * 1000 / hz;
                if (ms > 0) {
                    UserEntry *u = find_user(uid);
                    if (u)
                        u->cpu_ms += ms;
                }
                slot->prev_jiffies = jiffies;
            }

        } else if (!is_baseline) {
            /* Known process: accumulate the delta since the last sample. */
            long long delta = jiffies - slot->prev_jiffies;
            if (delta < 0)
                delta = 0;   /* should not happen; guard against weirdness */
            slot->prev_jiffies = jiffies;

            if (delta > 0) {
                long long ms = delta * 1000 / hz;
                UserEntry *u = find_user(uid);
                if (u)
                    u->cpu_ms += ms;
            }
        }
    }

    closedir(proc_dir);
}

/* -------------------------------------------------------------------------
 * Sorting and output
 * ---------------------------------------------------------------------- */

static int cmp_cpu_desc(const void *a, const void *b)
{
    long long da = ((const UserEntry *)a)->cpu_ms;
    long long db = ((const UserEntry *)b)->cpu_ms;
    return (db > da) ? 1 : (db < da) ? -1 : 0;
}

/* -------------------------------------------------------------------------
 * main
 * ---------------------------------------------------------------------- */

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <seconds>\n", argv[0]);
        return 1;
    }

    int duration = atoi(argv[1]);
    if (duration <= 0) {
        fprintf(stderr, "Error: duration must be a positive integer.\n");
        return 1;
    }

    hz = sysconf(_SC_CLK_TCK);
    if (hz <= 0)
        hz = 100;   /* safe fallback */

    /* ---- Phase 1: baseline snapshot ---- */
    do_sample(1);

    /* ---- Phase 2: one sample per second for <duration> seconds ---- */
    for (int i = 0; i < duration; i++) {
        sleep(1);
        do_sample(0);
    }

    /* ---- Phase 3: sort and print ---- */
    qsort(user_table, user_count, sizeof(UserEntry), cmp_cpu_desc);

    printf("%-4s %-20s %s\n", "Rank", "User", "CPU Time (milliseconds)");
    printf("----------------------------------------\n");

    int rank = 1;
    for (int i = 0; i < user_count; i++) {
        if (user_table[i].cpu_ms <= 0)
            continue;
        printf("%-4d %-20s %lld\n",
               rank++, user_table[i].name, user_table[i].cpu_ms);
    }

    return 0;
}
