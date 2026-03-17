#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>

static int pass_count = 0;
static int fail_count = 0;

struct mem_ops {
	long mmap_count, mmap_bytes;
	long munmap_count, munmap_bytes;
	long mprotect_count, mprotect_bytes;
	long brk_count, brk_bytes;
};

static int read_mem_ops(pid_t pid, struct mem_ops *ops)
{
	char path[256];
	FILE *f;

	snprintf(path, sizeof(path), "/proc/%d/mem_ops", pid);
	f = fopen(path, "r");
	if (!f)
		return -1;
	if (fscanf(f, "mmap %ld %ld\n", &ops->mmap_count, &ops->mmap_bytes) != 2)
		goto fail;
	if (fscanf(f, "munmap %ld %ld\n", &ops->munmap_count, &ops->munmap_bytes) != 2)
		goto fail;
	if (fscanf(f, "mprotect %ld %ld\n", &ops->mprotect_count, &ops->mprotect_bytes) != 2)
		goto fail;
	if (fscanf(f, "brk %ld %ld\n", &ops->brk_count, &ops->brk_bytes) != 2)
		goto fail;
	fclose(f);
	return 0;
fail:
	fclose(f);
	return -1;
}

static void check(const char *test, int condition)
{
	if (condition) {
		printf("  PASS: %s\n", test);
		pass_count++;
	} else {
		printf("  FAIL: %s\n", test);
		fail_count++;
	}
}

int main(void)
{
	struct mem_ops before, after;
	void *p;
	pid_t child;
	int status;

	printf("========================================\n");
	printf("Task 1 Comprehensive Test Suite\n");
	printf("========================================\n\n");

	/* ---- TEST 1: Successful mmap ---- */
	printf("[Test 1] Successful mmap\n");
	read_mem_ops(getpid(), &before);
	p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	read_mem_ops(getpid(), &after);
	check("mmap_count +1", after.mmap_count == before.mmap_count + 1);
	check("mmap_bytes +4096", after.mmap_bytes == before.mmap_bytes + 4096);

	/* ---- TEST 2: Successful mprotect ---- */
	printf("\n[Test 2] Successful mprotect\n");
	read_mem_ops(getpid(), &before);
	mprotect(p, 4096, PROT_READ);
	read_mem_ops(getpid(), &after);
	check("mprotect_count +1", after.mprotect_count == before.mprotect_count + 1);
	check("mprotect_bytes +4096", after.mprotect_bytes == before.mprotect_bytes + 4096);

	/* ---- TEST 3: Successful munmap ---- */
	printf("\n[Test 3] Successful munmap\n");
	read_mem_ops(getpid(), &before);
	munmap(p, 4096);
	read_mem_ops(getpid(), &after);
	check("munmap_count +1", after.munmap_count == before.munmap_count + 1);
	check("munmap_bytes +4096", after.munmap_bytes == before.munmap_bytes + 4096);

	/* ---- TEST 4: Failed mmap (invalid flags) ---- */
	printf("\n[Test 4] Failed mmap (MAP_SHARED|MAP_PRIVATE)\n");
	read_mem_ops(getpid(), &before);
	p = mmap(NULL, 4096, PROT_READ, MAP_SHARED | MAP_PRIVATE, -1, 0);
	read_mem_ops(getpid(), &after);
	check("mmap_count unchanged", after.mmap_count == before.mmap_count);
	check("mmap_bytes unchanged", after.mmap_bytes == before.mmap_bytes);

	/* ---- TEST 5: Failed mmap (bad fd) ---- */
	printf("\n[Test 5] Failed mmap (bad fd)\n");
	read_mem_ops(getpid(), &before);
	p = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, 9999, 0);
	read_mem_ops(getpid(), &after);
	check("mmap_count unchanged", after.mmap_count == before.mmap_count);
	check("mmap_bytes unchanged", after.mmap_bytes == before.mmap_bytes);

	/* ---- TEST 6: Failed munmap (bad address) ---- */
	printf("\n[Test 6] Failed munmap (bad address)\n");
	read_mem_ops(getpid(), &before);
	munmap((void *)0xdeadbeef, 4096);
	read_mem_ops(getpid(), &after);
	check("munmap_count unchanged", after.munmap_count == before.munmap_count);
	check("munmap_bytes unchanged", after.munmap_bytes == before.munmap_bytes);

	/* ---- TEST 7: Failed mprotect (bad address) ---- */
	printf("\n[Test 7] Failed mprotect (bad address)\n");
	read_mem_ops(getpid(), &before);
	mprotect((void *)0xdeadbeef, 4096, PROT_READ);
	read_mem_ops(getpid(), &after);
	check("mprotect_count unchanged", after.mprotect_count == before.mprotect_count);
	check("mprotect_bytes unchanged", after.mprotect_bytes == before.mprotect_bytes);

	/* ---- TEST 8: Failed mprotect (bad prot flags) ---- */
	printf("\n[Test 8] Failed mprotect (unmapped region)\n");
	read_mem_ops(getpid(), &before);
	mprotect((void *)0x1000000, 4096, PROT_READ | PROT_WRITE);
	read_mem_ops(getpid(), &after);
	check("mprotect_count unchanged", after.mprotect_count == before.mprotect_count);
	check("mprotect_bytes unchanged", after.mprotect_bytes == before.mprotect_bytes);

	/* ---- TEST 9: brk grow ---- */
	printf("\n[Test 9] brk grow (+8192)\n");
	void *old_brk = sbrk(0);
	read_mem_ops(getpid(), &before);
	sbrk(8192);
	read_mem_ops(getpid(), &after);
	check("brk_count +1", after.brk_count == before.brk_count + 1);
	check("brk_bytes +8192", after.brk_bytes == before.brk_bytes + 8192);

	/* ---- TEST 10: brk shrink ---- */
	printf("\n[Test 10] brk shrink (-8192)\n");
	read_mem_ops(getpid(), &before);
	brk(old_brk);
	read_mem_ops(getpid(), &after);
	check("brk_count +1", after.brk_count == before.brk_count + 1);
	check("brk_bytes +8192 (absolute)", after.brk_bytes == before.brk_bytes + 8192);

	/* ---- TEST 11: brk no-op ---- */
	printf("\n[Test 11] brk no-op (same address)\n");
	void *cur_brk = sbrk(0);
	read_mem_ops(getpid(), &before);
	brk(cur_brk);
	read_mem_ops(getpid(), &after);
	check("brk_count unchanged", after.brk_count == before.brk_count);
	check("brk_bytes unchanged", after.brk_bytes == before.brk_bytes);

	/* ---- TEST 12: Multiple mmap calls ---- */
	printf("\n[Test 12] Multiple mmap (3x different sizes)\n");
	read_mem_ops(getpid(), &before);
	void *p1 = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	void *p2 = mmap(NULL, 8192, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	void *p3 = mmap(NULL, 16384, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	read_mem_ops(getpid(), &after);
	check("mmap_count +3", after.mmap_count == before.mmap_count + 3);
	check("mmap_bytes +28672", after.mmap_bytes == before.mmap_bytes + 4096 + 8192 + 16384);
	munmap(p1, 4096);
	munmap(p2, 8192);
	munmap(p3, 16384);

	/* ---- TEST 13: Large mmap ---- */
	printf("\n[Test 13] Large mmap (1MB)\n");
	read_mem_ops(getpid(), &before);
	p = mmap(NULL, 1048576, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	read_mem_ops(getpid(), &after);
	check("mmap_count +1", after.mmap_count == before.mmap_count + 1);
	check("mmap_bytes +1048576", after.mmap_bytes == before.mmap_bytes + 1048576);
	munmap(p, 1048576);

	/* ---- TEST 14: mmap then munmap same region ---- */
	printf("\n[Test 14] mmap+munmap same region (65536)\n");
	read_mem_ops(getpid(), &before);
	p = mmap(NULL, 65536, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	munmap(p, 65536);
	read_mem_ops(getpid(), &after);
	check("mmap_count +1", after.mmap_count == before.mmap_count + 1);
	check("mmap_bytes +65536", after.mmap_bytes == before.mmap_bytes + 65536);
	check("munmap_count +1", after.munmap_count == before.munmap_count + 1);
	check("munmap_bytes +65536", after.munmap_bytes == before.munmap_bytes + 65536);

	/* ---- TEST 15: fork — child counters zero ---- */
	printf("\n[Test 15] fork — child counters should be zero\n");
	child = fork();
	if (child == 0) {
		struct mem_ops child_ops;
		read_mem_ops(getpid(), &child_ops);
		/* Write results to a file for parent to check */
		FILE *f = fopen("/tmp/child_result", "w");
		fprintf(f, "%ld %ld %ld %ld %ld %ld %ld %ld\n",
			child_ops.mmap_count, child_ops.mmap_bytes,
			child_ops.munmap_count, child_ops.munmap_bytes,
			child_ops.mprotect_count, child_ops.mprotect_bytes,
			child_ops.brk_count, child_ops.brk_bytes);
		fclose(f);
		_exit(0);
	}
	waitpid(child, &status, 0);
	{
		struct mem_ops child_ops;
		FILE *f = fopen("/tmp/child_result", "r");
		fscanf(f, "%ld %ld %ld %ld %ld %ld %ld %ld",
		       &child_ops.mmap_count, &child_ops.mmap_bytes,
		       &child_ops.munmap_count, &child_ops.munmap_bytes,
		       &child_ops.mprotect_count, &child_ops.mprotect_bytes,
		       &child_ops.brk_count, &child_ops.brk_bytes);
		fclose(f);
		check("child mmap_count == 0", child_ops.mmap_count == 0);
		check("child mmap_bytes == 0", child_ops.mmap_bytes == 0);
		check("child munmap_count == 0", child_ops.munmap_count == 0);
		check("child munmap_bytes == 0", child_ops.munmap_bytes == 0);
		check("child mprotect_count == 0", child_ops.mprotect_count == 0);
		check("child mprotect_bytes == 0", child_ops.mprotect_bytes == 0);
		check("child brk_count == 0", child_ops.brk_count == 0);
		check("child brk_bytes == 0", child_ops.brk_bytes == 0);
	}

	/* ---- TEST 16: fork — child does ops, parent unchanged ---- */
	printf("\n[Test 16] fork — child ops don't affect parent\n");
	read_mem_ops(getpid(), &before);
	child = fork();
	if (child == 0) {
		/* Child does some operations */
		void *cp = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (cp != MAP_FAILED) {
			mprotect(cp, 4096, PROT_READ);
			munmap(cp, 4096);
		}
		sbrk(4096);
		_exit(0);
	}
	waitpid(child, &status, 0);
	read_mem_ops(getpid(), &after);
	check("parent mmap_count unchanged", after.mmap_count == before.mmap_count);
	check("parent munmap_count unchanged", after.munmap_count == before.munmap_count);
	check("parent mprotect_count unchanged", after.mprotect_count == before.mprotect_count);
	check("parent brk_count unchanged", after.brk_count == before.brk_count);

	/* ---- TEST 17: child does mmap, verify child's own count ---- */
	printf("\n[Test 17] Child does 2 mmaps, verify child counts\n");
	child = fork();
	if (child == 0) {
		struct mem_ops c_before, c_after;
		read_mem_ops(getpid(), &c_before);
		mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		mmap(NULL, 8192, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		read_mem_ops(getpid(), &c_after);
		FILE *f = fopen("/tmp/child_result2", "w");
		fprintf(f, "%ld %ld\n",
			c_after.mmap_count - c_before.mmap_count,
			c_after.mmap_bytes - c_before.mmap_bytes);
		fclose(f);
		_exit(0);
	}
	waitpid(child, &status, 0);
	{
		long delta_count, delta_bytes;
		FILE *f = fopen("/tmp/child_result2", "r");
		fscanf(f, "%ld %ld", &delta_count, &delta_bytes);
		fclose(f);
		check("child mmap_count delta == 2", delta_count == 2);
		check("child mmap_bytes delta == 12288", delta_bytes == 12288);
	}

	/* ---- TEST 18: double fork — grandchild also zeroed ---- */
	printf("\n[Test 18] Double fork — grandchild counters zero\n");
	child = fork();
	if (child == 0) {
		/* Child does some ops first */
		mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		pid_t grandchild = fork();
		if (grandchild == 0) {
			struct mem_ops gc_ops;
			read_mem_ops(getpid(), &gc_ops);
			FILE *f = fopen("/tmp/gc_result", "w");
			fprintf(f, "%ld %ld %ld %ld %ld %ld %ld %ld\n",
				gc_ops.mmap_count, gc_ops.mmap_bytes,
				gc_ops.munmap_count, gc_ops.munmap_bytes,
				gc_ops.mprotect_count, gc_ops.mprotect_bytes,
				gc_ops.brk_count, gc_ops.brk_bytes);
			fclose(f);
			_exit(0);
		}
		waitpid(grandchild, &status, 0);
		_exit(0);
	}
	waitpid(child, &status, 0);
	{
		struct mem_ops gc_ops;
		FILE *f = fopen("/tmp/gc_result", "r");
		fscanf(f, "%ld %ld %ld %ld %ld %ld %ld %ld",
		       &gc_ops.mmap_count, &gc_ops.mmap_bytes,
		       &gc_ops.munmap_count, &gc_ops.munmap_bytes,
		       &gc_ops.mprotect_count, &gc_ops.mprotect_bytes,
		       &gc_ops.brk_count, &gc_ops.brk_bytes);
		fclose(f);
		check("grandchild all counters == 0",
		      gc_ops.mmap_count == 0 && gc_ops.mmap_bytes == 0 &&
		      gc_ops.munmap_count == 0 && gc_ops.munmap_bytes == 0 &&
		      gc_ops.mprotect_count == 0 && gc_ops.mprotect_bytes == 0 &&
		      gc_ops.brk_count == 0 && gc_ops.brk_bytes == 0);
	}

	/* ---- SUMMARY ---- */
	printf("\n========================================\n");
	printf("Results: %d passed, %d failed, %d total\n",
	       pass_count, fail_count, pass_count + fail_count);
	printf("========================================\n");

	return fail_count > 0 ? 1 : 0;
}
