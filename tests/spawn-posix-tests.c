/*
 * Process Spawn Manager
 *
 * Copyright (C) 2026 secunet Security Networks AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 */

#define _GNU_SOURCE

#include "spawn-posix.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define SPECIAL_ARGUMENT "space\tquote'\"\\glob*?[$(not-shell)]"
#define CONTAINMENT_EXIT_STATUS 125

static unsigned int passed;
/* Test-only linker wrappers inject one precise supervision failure each. */
static pid_t wrapper_owner = -1;
static int fail_group_termination_once;
static int fail_parent_setpgid_once;
static int fail_proc_scan_once;
static int fail_proc_read_once;
static int fail_close_range_once;
static int fail_pidfd_open_once;
static int fail_waitpid_once;
static int fail_group_reap_once;
static int stall_leader_reap;
static int group_signal_after_reap;
static int interrupt_waitpid_once;
static int track_group_lifetime;
static const char *group_setup_wait_path;
static pid_t tracked_group = -1;
static int tracked_leader_reaped;
static int signal_marker_fd = -1;
static int lifecycle_marker_fd = -1;
static atomic_int pause_parent_after_fork;
static atomic_int parent_fork_paused;
static atomic_int release_parent_fork;
static atomic_int termination_call_started;
static atomic_int termination_call_finished;
static atomic_int pause_group_reap_once;
static atomic_int group_reap_paused;
static atomic_int release_group_reap;
static char setuid_fixture_directory[PATH_MAX];
static char setuid_fixture_path[PATH_MAX];

DIR *__real_opendir(const char *path);
struct dirent *__real_readdir(DIR *directory);
pid_t __real_fork(void);
int __real_kill(pid_t pid, int signal);
int __real_setpgid(pid_t pid, pid_t group);
long __real_syscall(long number, ...);
pid_t __real_waitpid(pid_t pid, int *status, int options);

/* Fail the first parent-side SIGTERM sent to a request process group. */
int __wrap_kill(pid_t pid, int signal)
{
	if (getpid() == wrapper_owner && track_group_lifetime
	    && pid == -tracked_group && tracked_leader_reaped) {
		char marker = 'r';

		group_signal_after_reap = 1;
		if (lifecycle_marker_fd >= 0)
			(void)write(lifecycle_marker_fd, &marker, sizeof(marker));
	}
	if (getpid() == wrapper_owner && pid < 0 && signal == SIGTERM
	    && fail_group_termination_once) {
		fail_group_termination_once = 0;
		errno = EPERM;
		return -1;
	}
	return __real_kill(pid, signal);
}

/* Hold one parent immediately after fork so shutdown races publication. */
pid_t __wrap_fork(void)
{
	pid_t pid = __real_fork();

	if (pid > 0 && getpid() == wrapper_owner
	    && atomic_exchange(&pause_parent_after_fork, 0)) {
		atomic_store(&parent_fork_paused, 1);
		while (!atomic_load(&release_parent_fork)) {
			struct timespec pause = { 0, 1000 * 1000 };

			(void)nanosleep(&pause, NULL);
		}
	}
	return pid;
}

/* Hide /proc/self/fd once so close_range must carry descriptor cleanup. */
DIR *__wrap_opendir(const char *path)
{
	if (getpid() == wrapper_owner && fail_proc_scan_once
	    && strcmp(path, "/proc/self/fd") == 0) {
		fail_proc_scan_once = 0;
		errno = ENOENT;
		return NULL;
	}
	return __real_opendir(path);
}

/* Interrupt one procfs scan so the descriptor-limit fallback is required. */
struct dirent *__wrap_readdir(DIR *directory)
{
	if (getpid() == wrapper_owner && fail_proc_read_once) {
		fail_proc_read_once = 0;
		errno = EINTR;
		return NULL;
	}
	return __real_readdir(directory);
}

/* Fail the first parent-side attempt to establish the request group. */
int __wrap_setpgid(pid_t pid, pid_t group)
{
	if (getpid() == wrapper_owner && pid > 0
	    && fail_parent_setpgid_once) {
		if (group_setup_wait_path != NULL) {
			for (int attempt = 0; attempt < 100; ++attempt) {
				struct stat status;
				struct timespec pause = { 0, 10 * 1000 * 1000 };

				if (stat(group_setup_wait_path, &status) == 0
				    && status.st_size > 0)
					break;
				(void)nanosleep(&pause, NULL);
			}
		}
		fail_parent_setpgid_once = 0;
		errno = EPERM;
		return -1;
	}
	if (getpid() == wrapper_owner && track_group_lifetime
	    && pid > 0 && group == pid)
		tracked_group = pid;
	return __real_setpgid(pid, group);
}

/* Inject close_range failure while forwarding every supported core syscall. */
long __wrap_syscall(long number, ...)
{
	va_list arguments;

	va_start(arguments, number);
#ifdef SYS_close_range
	if (number == SYS_close_range) {
		unsigned int first = va_arg(arguments, unsigned int);
		unsigned int last = va_arg(arguments, unsigned int);
		unsigned int flags = va_arg(arguments, unsigned int);

		va_end(arguments);
		if (getppid() == wrapper_owner && fail_close_range_once) {
			fail_close_range_once = 0;
			errno = ENOSYS;
			return -1;
		}
		return __real_syscall(number, first, last, flags);
	}
#endif
#ifdef SYS_pidfd_open
	if (number == SYS_pidfd_open) {
		pid_t pid = va_arg(arguments, pid_t);
		unsigned int flags = va_arg(arguments, unsigned int);

		va_end(arguments);
		if (getpid() == wrapper_owner && fail_pidfd_open_once) {
			fail_pidfd_open_once = 0;
			errno = EPERM;
			return -1;
		}
		return __real_syscall(number, pid, flags);
	}
#endif
	va_end(arguments);
	errno = ENOSYS;
	return -1;
}

/* Interrupt the first blocking parent wait selected by one regression. */
pid_t __wrap_waitpid(pid_t pid, int *status, int options)
{
	pid_t waited;

	if (getpid() == wrapper_owner && pid < 0 && options == WNOHANG
	    && atomic_exchange(&pause_group_reap_once, 0)) {
		/* The leader is retired, but its adopted child is not reaped yet. */
		atomic_store(&group_reap_paused, 1);
		while (!atomic_load(&release_group_reap)) {
			struct timespec pause = { 0, 1000 * 1000 };

			(void)nanosleep(&pause, NULL);
		}
	}

	if (getpid() == wrapper_owner && pid < 0 && options == WNOHANG
	    && fail_group_reap_once) {
		fail_group_reap_once = 0;
		errno = EIO;
		return -1;
	}

	if (getpid() == wrapper_owner && pid > 0
	    && (options == 0 || options == WNOHANG)
	    && interrupt_waitpid_once) {
		interrupt_waitpid_once = 0;
		errno = EINTR;
		return -1;
	}
	if (getpid() == wrapper_owner && pid > 0 && options == 0
	    && fail_waitpid_once) {
		fail_waitpid_once = 0;
		errno = EIO;
		return -1;
	}
	if (getpid() == wrapper_owner && pid > 0 && options == WNOHANG
	    && stall_leader_reap)
		return 0;
	waited = __real_waitpid(pid, status, options);
	if (getpid() == wrapper_owner && track_group_lifetime
	    && pid == tracked_group && waited == pid)
		tracked_leader_reaped = 1;
	return waited;
}

/* Record whether a forked child enters an inherited manager signal handler. */
static void record_inherited_signal(int signal_number)
{
	char marker = 's';
	int saved_errno = errno;

	(void)signal_number;
	if (signal_marker_fd >= 0)
		(void)write(signal_marker_fd, &marker, sizeof(marker));
	errno = saved_errno;
}

static void fail(const char *message)
{
	fprintf(stderr, "FAIL POSIX core: %s\n", message);
	exit(1);
}

static void pass(const char *message)
{
	++passed;
	printf("PASS POSIX core: %s\n", message);
}

static void require(int condition, const char *message)
{
	if (!condition)
		fail(message);
}

static char *read_file(const char *path)
{
	struct stat status;
	char *content;
	FILE *file;
	size_t count;

	require(stat(path, &status) == 0, "stat output");
	content = malloc((size_t)status.st_size + 1);
	require(content != NULL, "allocate output");
	file = fopen(path, "r");
	require(file != NULL, "open output");
	count = fread(content, 1, (size_t)status.st_size, file);
	require(count == (size_t)status.st_size, "read output");
	require(fclose(file) == 0, "close output");
	content[count] = '\0';
	return content;
}

/* Remove the privileged fixture even when a test assertion exits early. */
static void cleanup_setuid_fixture(void)
{
	if (setuid_fixture_path[0] != '\0') {
		(void)unlink(setuid_fixture_path);
		setuid_fixture_path[0] = '\0';
	}
	if (setuid_fixture_directory[0] != '\0') {
		(void)rmdir(setuid_fixture_directory);
		setuid_fixture_directory[0] = '\0';
	}
}

/* Create one root-owned set-user-ID copy for the containment exec oracle. */
static void create_setuid_copy(const char *source, const char *target)
{
	char buffer[4096];
	int input;
	int output;
	ssize_t count;

	input = open(source, O_RDONLY);
	require(input >= 0, "open setuid fixture source");
	output = open(target, O_WRONLY | O_CREAT | O_EXCL, 0700);
	require(output >= 0, "create setuid fixture target");
	while ((count = read(input, buffer, sizeof(buffer))) > 0) {
		ssize_t offset = 0;

		while (offset < count) {
			ssize_t written = write(
				output, buffer + offset, (size_t)(count - offset));

			require(written > 0, "write setuid fixture target");
			offset += written;
		}
	}
	require(count == 0, "read setuid fixture source");
	require(fchmod(output, 04755) == 0, "mark setuid fixture target");
	require(close(output) == 0 && close(input) == 0,
		"close setuid fixture files");
}

static void require_exited(
	const struct spawn_posix_result *result,
	int status,
	const char *message)
{
	require(result->kind == SPAWN_POSIX_EXITED, message);
	require(result->exit_status == status, message);
}

static double monotonic_seconds(void)
{
	struct timespec now;

	require(clock_gettime(CLOCK_MONOTONIC, &now) == 0, "read monotonic clock");
	return (double)now.tv_sec + (double)now.tv_nsec / 1000000000.0;
}

static int compare_samples(const void *left, const void *right)
{
	double lhs = *(const double *)left;
	double rhs = *(const double *)right;

	return lhs < rhs ? -1 : lhs > rhs;
}

static int benchmark(void)
{
	enum { sample_count = 1000 };
	char *empty_environment[] = { NULL };
	char *arguments[] = { "/bin/true", NULL };
	struct spawn_posix_result result;
	double samples[sample_count];
	double total = 0.0;

	for (size_t index = 0; index < sample_count; ++index) {
		double started = monotonic_seconds();
		require(spawn_posix_execute(
			"/bin/true", arguments, 0, empty_environment, "/", 0, NULL,
			0, NULL, -1, &result) == 0, "benchmark execute");
		require_exited(&result, 0, "benchmark result");
		samples[index] = monotonic_seconds() - started;
		total += samples[index];
	}
	qsort(samples, sample_count, sizeof(samples[0]), compare_samples);
	printf("* POSIX direct /bin/true mean=% .9f median=% .9f p95=% .9f\n",
		total / sample_count, samples[sample_count / 2],
		samples[(sample_count * 95 + 99) / 100 - 1]);
	return 0;
}

static int fixture_verify(int argc, char *argv[], char *envp[])
{
	char cwd[PATH_MAX];
	char expected_cwd[PATH_MAX + 16];

	if (argc != 5 || argv[3][0] != '\0'
	    || strcmp(argv[4], SPECIAL_ARGUMENT) != 0)
		return 81;
	if (envp[0] == NULL || envp[1] == NULL || envp[2] != NULL
	    || strcmp(envp[0], "ONLY=visible value") != 0
	    || strncmp(envp[1], "EXPECTED_CWD=", 13) != 0)
		return 82;
	if (getcwd(cwd, sizeof(cwd)) == NULL)
		return 83;
	if (snprintf(expected_cwd, sizeof(expected_cwd), "EXPECTED_CWD=%s", cwd)
	    >= (int)sizeof(expected_cwd)
	    || strcmp(envp[1], expected_cwd) != 0)
		return 84;
	if (write(STDOUT_FILENO, "verified stdout\n", 16) != 16
	    || write(STDERR_FILENO, "verified stderr\n", 16) != 16)
		return 85;
	return 0;
}

static int fixture_tree(void)
{
	pid_t descendant = fork();

	if (descendant < 0)
		return 86;
	if (descendant == 0) {
		for (;;)
			pause();
	}
	printf("%ld\n", (long)descendant);
	fflush(stdout);
	for (;;)
		pause();
}

static int fixture_orphan(void)
{
	pid_t descendant = fork();

	if (descendant < 0)
		return 95;
	if (descendant == 0) {
		for (;;)
			pause();
	}
	printf("%ld\n", (long)descendant);
	fflush(stdout);
	return 0;
}

static int write_repeated(int descriptor, size_t count, char value)
{
	char buffer[4096];

	memset(buffer, value, sizeof(buffer));
	while (count > 0) {
		size_t chunk = count < sizeof(buffer) ? count : sizeof(buffer);
		ssize_t written;

		do {
			written = write(descriptor, buffer, chunk);
		} while (written < 0 && errno == EINTR);
		if (written <= 0)
			return -1;
		count -= (size_t)written;
	}
	return 0;
}

static int fixture_output(int argc, char *argv[])
{
	char *end;
	unsigned long count;

	if (argc != 4)
		return 91;
	errno = 0;
	count = strtoul(argv[3], &end, 10);
	if (errno != 0 || *end != '\0' || count > 1024 * 1024)
		return 92;
	if (write_repeated(STDOUT_FILENO, count, 'o') < 0)
		return 93;
	if (write_repeated(STDERR_FILENO, count, 'e') < 0)
		return 94;
	return 0;
}

static int fixture(int argc, char *argv[], char *envp[])
{
	if (argc < 3)
		return 80;
	if (strcmp(argv[2], "verify") == 0)
		return fixture_verify(argc, argv, envp);
	if (strcmp(argv[2], "exit37") == 0)
		return 37;
	if (strcmp(argv[2], "signal") == 0) {
		raise(SIGTERM);
		return 87;
	}
	if (strcmp(argv[2], "stdin") == 0) {
		char byte;
		return read(STDIN_FILENO, &byte, 1) == 0 ? 0 : 88;
	}
	if (strcmp(argv[2], "parent") == 0) {
		printf("%ld\n", (long)getppid());
		return 0;
	}
	if (strcmp(argv[2], "fd") == 0 && argc == 4) {
		int fd = atoi(argv[3]);
		return fcntl(fd, F_GETFD) < 0 && errno == EBADF ? 0 : 89;
	}
	if (strcmp(argv[2], "output") == 0)
		return fixture_output(argc, argv);
	if (strcmp(argv[2], "tree") == 0)
		return fixture_tree();
	if (strcmp(argv[2], "orphan") == 0)
		return fixture_orphan();
	if (strcmp(argv[2], "containment") == 0) {
		int parent_signal = 0;
		char *end;
		long expected_uid;

		if (argc != 4)
			return 97;
		errno = 0;
		expected_uid = strtol(argv[3], &end, 10);
		if (errno != 0 || *end != '\0' || expected_uid != geteuid())
			return 98;
		if (prctl(PR_GET_PDEATHSIG, &parent_signal) < 0
		    || parent_signal != SIGKILL)
			return 99;
		return prctl(PR_GET_NO_NEW_PRIVS, 0L, 0L, 0L, 0L) == 1
			? 0 : 100;
	}
	return 90;
}

/* Run one SIGCHLD inheritance case in a fresh process image. */
static int fixture_inherited_sigchld(
	const char *self,
	const char *sigchld_case)
{
	char *empty_environment[] = { NULL };
	char *arguments[] = { (char *)self, "fixture", "exit37", NULL };
	struct spawn_posix_result result;
	struct sigaction action = { 0 };

	if (strcmp(sigchld_case, "ignore") == 0)
		action.sa_handler = SIG_IGN;
	else if (strcmp(sigchld_case, "no-cld-wait") == 0) {
		action.sa_handler = SIG_DFL;
		action.sa_flags = SA_NOCLDWAIT;
	} else
		return 91;
	if (sigemptyset(&action.sa_mask) < 0
	    || sigaction(SIGCHLD, &action, NULL) < 0)
		return 92;
	if (spawn_posix_execute(
		self, arguments, 0, empty_environment, "/", 0, NULL,
		0, NULL, 1000, &result) != 0
	    || result.kind != SPAWN_POSIX_EXITED
	    || result.exit_status != 37)
		return 93;
	return 0;
}

static void test_exit_and_signal(const char *self)
{
	char *empty_environment[] = { NULL };
	char *exit_arguments[] = { (char *)self, "fixture", "exit37", NULL };
	char *signal_arguments[] = { (char *)self, "fixture", "signal", NULL };
	struct spawn_posix_result result;

	require(spawn_posix_execute(
		self, exit_arguments, 0, empty_environment, "/", 0, NULL, 0,
		NULL, 1000, &result) == 0, "execute exit fixture");
	require_exited(&result, 37, "exact exit status");
	require(spawn_posix_execute(
		self, signal_arguments, 0, empty_environment, "/", 0, NULL, 0,
		NULL, 1000, &result) == 0, "execute signal fixture");
	require(result.kind == SPAWN_POSIX_SIGNALED
		&& result.signal_number == SIGTERM, "exact signal");
	require(spawn_posix_execute(
		self, exit_arguments, 0, empty_environment, "/", 0, NULL, 0,
		NULL, INT64_MAX, &result) == 0, "execute maximum-timeout fixture");
	require_exited(&result, 37, "maximum timeout result");
	pass("exact exit and signal results");
}

/* Prove inherited auto-reap policy cannot invalidate exact child ownership. */
static void test_inherited_sigchld_disposition(const char *self)
{
	for (int sigchld_case = 0; sigchld_case < 2; ++sigchld_case) {
		const char *case_name = sigchld_case == 0
			? "ignore" : "no-cld-wait";
		pid_t supervisor;
		int supervisor_status;

		supervisor = fork();
		require(supervisor >= 0, "fork SIGCHLD supervisor");
		if (supervisor == 0) {
			(void)execl(self, self, "sigchld-core", case_name, NULL);
			_exit(94);
		}
		require(__real_waitpid(
			supervisor, &supervisor_status, 0) == supervisor,
			"wait for SIGCHLD supervisor");
		require(WIFEXITED(supervisor_status)
			&& WEXITSTATUS(supervisor_status) == 0,
			"inherited SIGCHLD policy broke exact child ownership");
	}
	pass("manager normalizes inherited SIGCHLD disposition");
}

static void test_child_containment_state(const char *self)
{
	char *empty_environment[] = { NULL };
	char uid_text[32];
	char *arguments[] = {
		(char *)self, "fixture", "containment", uid_text, NULL
	};
	struct spawn_posix_result result;

	require(snprintf(uid_text, sizeof(uid_text), "%ld", (long)geteuid())
		< (int)sizeof(uid_text), "format containment uid");
	require(spawn_posix_execute(
		self, arguments, 0, empty_environment, "/", 0, NULL, 0, NULL,
		1000, &result) == 0, "execute child containment fixture");
	require_exited(&result, 0, "child containment state");
	if (geteuid() == 0) {
		char directory_template[] = "/tmp/spawn-posix-setuid-XXXXXX";
		pid_t supervisor;
		int supervisor_status;

		require(atexit(cleanup_setuid_fixture) == 0,
			"register setuid fixture cleanup");
		require(mkdtemp(directory_template) != NULL,
			"create private setuid fixture directory");
		require(snprintf(setuid_fixture_directory,
			sizeof(setuid_fixture_directory), "%s", directory_template)
			< (int)sizeof(setuid_fixture_directory),
			"record setuid fixture directory");
		require(chown(setuid_fixture_directory, 65534, 65534) == 0,
			"delegate private setuid fixture directory");
		require(snprintf(setuid_fixture_path, sizeof(setuid_fixture_path),
			"%s/target", setuid_fixture_directory)
			< (int)sizeof(setuid_fixture_path),
			"construct setuid fixture path");
		create_setuid_copy(self, setuid_fixture_path);
		supervisor = fork();
		require(supervisor >= 0, "fork setuid containment supervisor");
		if (supervisor == 0) {
			char *setuid_arguments[] = {
				setuid_fixture_path, "fixture", "containment", "65534", NULL
			};
			struct spawn_posix_result setuid_result;

			if (setgid(65534) < 0 || setuid(65534) < 0)
				_exit(101);
			_exit(spawn_posix_execute(
				setuid_fixture_path, setuid_arguments, 0,
				empty_environment, "/",
				0, NULL, 0, NULL, 1000, &setuid_result) == 0
				&& setuid_result.kind == SPAWN_POSIX_EXITED
				&& setuid_result.exit_status == 0 ? 0 : 102);
		}
		require(__real_waitpid(
			supervisor, &supervisor_status, 0) == supervisor,
			"wait for setuid containment supervisor");
		require(WIFEXITED(supervisor_status)
			&& WEXITSTATUS(supervisor_status) == 0,
			"setuid exec lost parent-death containment");
		cleanup_setuid_fixture();
	}
	pass("child preserves parent-death containment");
}

static void test_error_pipe_duplication(const char *self)
{
	char *empty_environment[] = { NULL };
	char *arguments[] = { (char *)self, "fixture", "exit37", NULL };
	struct spawn_posix_result result;
	struct rlimit original_limit;
	struct rlimit limited_limit;
	int saved_stdin;
	int saved_stdout;
	int call_result;
	int restore_limit_result;
	int restore_stdin_result;
	int restore_stdout_result;

	require(spawn_posix_execute(
		self, arguments, 0, empty_environment, "/", 0, NULL, 0, NULL,
		1000, &result) == 0, "prepare descriptor ceiling");
	require_exited(&result, 37, "descriptor-ceiling preparation result");

	/*
	 * The preparation call caches the parent's descriptor ceiling. Free
	 * descriptors zero and one, then restrict new descriptors to 0..2 so
	 * pipe2 returns them and the child's dup2(error_write_fd, 3) fails with
	 * EBADF. The original implementation then lost the error record and
	 * reported exit 127; the dedicated pipe endpoint must preserve the
	 * structured failure.
	 */
	require(getrlimit(RLIMIT_NOFILE, &original_limit) == 0,
		"read descriptor limit");
	require(original_limit.rlim_cur >= 3, "descriptor limit supports fixture");
	saved_stdin = dup(STDIN_FILENO);
	saved_stdout = dup(STDOUT_FILENO);
	require(saved_stdin >= 0 && saved_stdout >= 0,
		"save standard descriptors");
	limited_limit = original_limit;
	limited_limit.rlim_cur = 3;
	require(setrlimit(RLIMIT_NOFILE, &limited_limit) == 0,
		"restrict descriptor limit");
	require(close(STDIN_FILENO) == 0 && close(STDOUT_FILENO) == 0,
		"free low descriptors");

	call_result = spawn_posix_execute(
		self, arguments, 0, empty_environment, "/", 0, NULL, 0, NULL,
		1000, &result);

	restore_limit_result = setrlimit(RLIMIT_NOFILE, &original_limit);
	restore_stdin_result = dup2(saved_stdin, STDIN_FILENO);
	restore_stdout_result = dup2(saved_stdout, STDOUT_FILENO);
	(void)close(saved_stdin);
	(void)close(saved_stdout);
	require(restore_limit_result == 0 && restore_stdin_result == STDIN_FILENO
		&& restore_stdout_result == STDOUT_FILENO,
		"restore descriptor environment");
	require(call_result == 0
		&& result.kind == SPAWN_POSIX_SPAWN_FAILED
		&& result.failure_stage == SPAWN_POSIX_CREATE_ERROR_PIPE
		&& result.error_number == EBADF,
		"report error-pipe duplication failure");
	pass("error-pipe duplication failure channel");
}

static void test_exec_failure(const char *self)
{
	char *empty_environment[] = { NULL };
	char *arguments[] = { (char *)self, NULL };
	struct spawn_posix_result result;

	require(spawn_posix_execute(
		"/definitely/missing/spawn-target", arguments, 0,
		empty_environment, "/", 0, NULL, 0, NULL, 1000, &result) == 0,
		"execute missing target");
	require(result.kind == SPAWN_POSIX_SPAWN_FAILED
		&& result.failure_stage == SPAWN_POSIX_EXEC
		&& result.error_number == ENOENT, "classify missing target");
	pass("pre-exec failure stage and errno");
}

static void test_request_data(
	const char *self,
	const char *directory,
	const char *stdout_path,
	const char *stderr_path)
{
	char expected_cwd[PATH_MAX + 16];
	char *environment[] = { "ONLY=visible value", expected_cwd, NULL };
	char *arguments[] = {
		(char *)self, "fixture", "verify", "", SPECIAL_ARGUMENT, NULL
	};
	struct spawn_posix_result result;
	struct stat stdout_status;
	struct stat stderr_status;
	char *stdout_content;
	char *stderr_content;

	require(snprintf(
		expected_cwd, sizeof(expected_cwd), "EXPECTED_CWD=%s", directory)
		< (int)sizeof(expected_cwd), "construct expected cwd");
	require(spawn_posix_execute(
		self, arguments, 0, environment, directory,
		SPAWN_POSIX_TRUNCATE_FILE, stdout_path,
		SPAWN_POSIX_TRUNCATE_FILE, stderr_path, 1000, &result) == 0,
		"execute request-data fixture");
	require_exited(&result, 0, "request-data result");
	require(stat(stdout_path, &stdout_status) == 0
		&& stat(stderr_path, &stderr_status) == 0,
		"stat split streams");
	require((stdout_status.st_mode & 0777) == 0644
		&& (stderr_status.st_mode & 0777) == 0644,
		"umask-filtered stream create modes");
	stdout_content = read_file(stdout_path);
	stderr_content = read_file(stderr_path);
	require(strcmp(stdout_content, "verified stdout\n") == 0,
		"independent stdout");
	require(strcmp(stderr_content, "verified stderr\n") == 0,
		"independent stderr");
	free(stdout_content);
	free(stderr_content);
	require(chmod(stdout_path, 0600) == 0
		&& chmod(stderr_path, 0640) == 0,
		"prepare existing stream modes");
	require(spawn_posix_execute(
		self, arguments, 0, environment, directory,
		SPAWN_POSIX_TRUNCATE_FILE, stdout_path,
		SPAWN_POSIX_TRUNCATE_FILE, stderr_path, 1000, &result) == 0,
		"truncate existing stream fixtures");
	require_exited(&result, 0, "existing-stream result");
	require(stat(stdout_path, &stdout_status) == 0
		&& stat(stderr_path, &stderr_status) == 0,
		"restat existing streams");
	require((stdout_status.st_mode & 0777) == 0600
		&& (stderr_status.st_mode & 0777) == 0640,
		"preserve existing stream modes");
	pass("argv, replacement environment, cwd and split streams");
}

static void test_stdin_and_descriptors(
	const char *self,
	int inherited_fd)
{
	char fd_text[32];
	char *empty_environment[] = { NULL };
	char *stdin_arguments[] = { (char *)self, "fixture", "stdin", NULL };
	char *fd_arguments[] = {
		(char *)self, "fixture", "fd", fd_text, NULL
	};
	struct spawn_posix_result result;

	require(spawn_posix_execute(
		self, stdin_arguments, 0, empty_environment, "/", 0, NULL, 0,
		NULL, 1000, &result) == 0, "execute stdin fixture");
	require_exited(&result, 0, "stdin is /dev/null");
	require(snprintf(fd_text, sizeof(fd_text), "%d", inherited_fd)
		< (int)sizeof(fd_text), "format descriptor");
	fd_arguments[3] = fd_text;
	require(spawn_posix_execute(
		self, fd_arguments, 0, empty_environment, "/", 0, NULL, 0,
		NULL, 1000, &result) == 0, "execute descriptor fixture");
	require_exited(&result, 0, "undeclared descriptor closed");
	pass("/dev/null stdin and descriptor closure");
}

static void test_stream_nofollow(
	const char *self,
	const char *symlink_path)
{
	char *empty_environment[] = { NULL };
	char *arguments[] = { (char *)self, "fixture", "exit37", NULL };
	struct spawn_posix_result result;

	require(symlink("/dev/null", symlink_path) == 0, "create stream symlink");
	require(spawn_posix_execute(
		self, arguments, 0, empty_environment, "/",
		SPAWN_POSIX_TRUNCATE_FILE, symlink_path, 0, NULL, 1000,
		&result) == 0, "execute nofollow fixture");
	require(result.kind == SPAWN_POSIX_SPAWN_FAILED
		&& result.failure_stage == SPAWN_POSIX_OPEN_STDOUT
		&& result.error_number == ELOOP, "reject stream symlink");
	require(unlink(symlink_path) == 0, "remove stream symlink");
	pass("nofollow stream failure");
}

static void test_child_signal_dispositions(const char *fifo_path)
{
	char *empty_environment[] = { NULL };
	char *arguments[] = { "/bin/true", NULL };
	struct spawn_posix_result result;
	struct sigaction action = { 0 };
	struct sigaction original;
	char marker;
	int marker_pipe[2];
	ssize_t count;

	require(mkfifo(fifo_path, 0600) == 0, "create signal fixture fifo");
	require(pipe2(marker_pipe, O_CLOEXEC | O_NONBLOCK) == 0,
		"create signal marker pipe");
	action.sa_handler = record_inherited_signal;
	require(sigemptyset(&action.sa_mask) == 0
		&& sigaction(SIGTERM, &action, &original) == 0,
		"install inherited signal fixture");
	signal_marker_fd = marker_pipe[1];
	require(spawn_posix_execute(
		"/bin/true", arguments, 0, empty_environment, "/",
		SPAWN_POSIX_TRUNCATE_FILE, fifo_path, 0, NULL, 50,
		&result) == 0, "execute blocked pre-exec signal fixture");
	signal_marker_fd = -1;
	require(sigaction(SIGTERM, &original, NULL) == 0,
		"restore signal disposition");
	require(close(marker_pipe[1]) == 0, "close signal marker writer");
	count = read(marker_pipe[0], &marker, sizeof(marker));
	require(close(marker_pipe[0]) == 0, "close signal marker reader");
	require(unlink(fifo_path) == 0, "remove signal fixture fifo");
	require(result.kind == SPAWN_POSIX_TIMED_OUT,
		"classify blocked pre-exec timeout");
	require(count == 0, "child entered inherited SIGTERM handler");
	pass("child resets inherited signal dispositions");
}

static void test_interrupted_group_setup_reap(void)
{
	char *empty_environment[] = { NULL };
	char *arguments[] = { "/bin/true", NULL };
	struct spawn_posix_result result;
	int status;
	pid_t waited;

	wrapper_owner = getpid();
	fail_parent_setpgid_once = 1;
	interrupt_waitpid_once = 1;
	require(spawn_posix_execute(
		"/bin/true", arguments, 0, empty_environment, "/", 0, NULL,
		0, NULL, -1, &result) < 0, "classify group setup failure");
	wrapper_owner = -1;
	require(result.kind == SPAWN_POSIX_INTERNAL_ERROR
		&& result.failure_stage == SPAWN_POSIX_PROCESS_GROUP,
		"report group setup failure");
	errno = 0;
	waited = __real_waitpid(-1, &status, WNOHANG);
	require(waited < 0 && errno == ECHILD,
		"interrupted group setup left an unreaped child");
	pass("EINTR preserves group setup reap ownership");
}

static void test_no_proc_descriptor_cleanup(void)
{
	char *empty_environment[] = { NULL };
	char *arguments[] = { "/bin/true", NULL };
	struct spawn_posix_result result;

	wrapper_owner = getpid();
	fail_proc_scan_once = 1;
	require(spawn_posix_execute(
		"/bin/true", arguments, 0, empty_environment, "/", 0, NULL,
		0, NULL, -1, &result) == 0, "execute without proc descriptor scan");
	require(!fail_proc_scan_once, "procfs open failure injection did not fire");
	wrapper_owner = -1;
	require_exited(&result, 0, "close_range without proc descriptor scan");
	pass("descriptor cleanup without procfs");
}

static void test_pidfd_fallback(void)
{
	char *empty_environment[] = { NULL };
	char *arguments[] = { "/bin/true", NULL };
	struct spawn_posix_result result;

	wrapper_owner = getpid();
	fail_pidfd_open_once = 1;
	require(spawn_posix_execute(
		"/bin/true", arguments, 0, empty_environment, "/", 0, NULL,
		0, NULL, 1000, &result) == 0, "execute without pidfd");
	wrapper_owner = -1;
	require(!fail_pidfd_open_once, "pidfd failure fixture was not used");
	require_exited(&result, 0, "polling fallback without pidfd");
	pass("pidfd failure uses polling fallback");
}

static void test_empty_descriptor_fallback(void)
{
	pid_t supervisor;
	int supervisor_status;

	supervisor = fork();
	require(supervisor >= 0, "fork empty-descriptor supervisor");
	if (supervisor == 0) {
		char *empty_environment[] = { NULL };
		char *arguments[] = { "/bin/true", NULL };
		struct spawn_posix_result result;
		int call_result;

#ifdef SYS_close_range
		(void)__real_syscall(SYS_close_range, 3U, ~0U, 0U);
#endif
		(void)close(STDIN_FILENO);
		(void)close(STDOUT_FILENO);
		wrapper_owner = getpid();
		fail_close_range_once = 1;
		call_result = spawn_posix_execute(
			"/bin/true", arguments, 0, empty_environment, "/", 0, NULL,
			0, NULL, -1, &result);
		_exit(call_result == 0 && result.kind == SPAWN_POSIX_EXITED
			&& result.exit_status == 0 ? 0 : 97);
	}
	require(__real_waitpid(supervisor, &supervisor_status, 0) == supervisor,
		"wait for empty-descriptor supervisor");
	require(WIFEXITED(supervisor_status)
		&& WEXITSTATUS(supervisor_status) == 0,
		"empty descriptor fallback was not a no-op");
	pass("empty descriptor fallback is a no-op");
}

/* A failed procfs scan must not publish its partial descriptor maximum. */
static void test_proc_scan_error_fallback(const char *self)
{
	pid_t supervisor;
	int supervisor_status;

	supervisor = fork();
	require(supervisor >= 0, "fork proc-scan supervisor");
	if (supervisor == 0) {
		char fd_text[32];
		char *empty_environment[] = { NULL };
		char *arguments[] = {
			(char *)self, "fixture", "fd", fd_text, NULL
		};
		struct spawn_posix_result result;
		struct rlimit limit;
		int source_fd;
		int inherited_fd;
		int call_result;

		if (getrlimit(RLIMIT_NOFILE, &limit) < 0
		    || limit.rlim_cur <= 100)
			_exit(101);
		if (limit.rlim_cur > 128) {
			limit.rlim_cur = 128;
			if (setrlimit(RLIMIT_NOFILE, &limit) < 0)
				_exit(102);
		}
		source_fd = open("/dev/null", O_RDONLY);
		if (source_fd < 0)
			_exit(103);
		inherited_fd = fcntl(source_fd, F_DUPFD, 100);
		if (inherited_fd < 100
		    || snprintf(fd_text, sizeof(fd_text), "%d", inherited_fd)
		       >= (int)sizeof(fd_text))
			_exit(104);

		wrapper_owner = getpid();
		fail_proc_read_once = 1;
		fail_close_range_once = 1;
		call_result = spawn_posix_execute(
			self, arguments, 0, empty_environment, "/", 0, NULL,
			0, NULL, -1, &result);
		_exit(call_result == 0 && !fail_proc_read_once
			&& result.kind == SPAWN_POSIX_EXITED
			&& result.exit_status == 0 ? 0 : 105);
	}
	require(__real_waitpid(supervisor, &supervisor_status, 0) == supervisor,
		"wait for proc-scan supervisor");
	require(WIFEXITED(supervisor_status)
		&& WEXITSTATUS(supervisor_status) == 0,
		"proc-scan error exposed an inherited descriptor");
	pass("procfs scan error uses descriptor-limit fallback");
}

static void test_group_setup_failure_descendants(
	const char *self,
	const char *pid_path)
{
	char *empty_environment[] = { NULL };
	char *arguments[] = { (char *)self, "fixture", "orphan", NULL };
	struct spawn_posix_result result;
	char *pid_content;
	pid_t descendant;
	pid_t waited;
	int descendant_status = 0;
	int wait_errno;

	wrapper_owner = getpid();
	group_setup_wait_path = pid_path;
	fail_parent_setpgid_once = 1;
	require(spawn_posix_execute(
		self, arguments, 0, empty_environment, "/",
		SPAWN_POSIX_TRUNCATE_FILE, pid_path, 0, NULL, -1,
		&result) < 0, "classify group setup descendant failure");
	group_setup_wait_path = NULL;
	wrapper_owner = -1;
	require(result.kind == SPAWN_POSIX_INTERNAL_ERROR
		&& result.failure_stage == SPAWN_POSIX_PROCESS_GROUP,
		"report group setup descendant failure");
	pid_content = read_file(pid_path);
	descendant = (pid_t)strtol(pid_content, NULL, 10);
	free(pid_content);
	require(descendant > 0, "read group setup descendant pid");
	errno = 0;
	waited = __real_waitpid(descendant, &descendant_status, WNOHANG);
	wait_errno = errno;
	if (waited == 0) {
		(void)__real_kill(descendant, SIGKILL);
		(void)__real_waitpid(descendant, &descendant_status, 0);
	}
	require(waited < 0 && wait_errno == ECHILD,
		"group setup failure left a descendant behind");
	pass("group setup failure contains descendants");
}

/* Prove an uncontained group makes its owning manager process fail-stop. */
static void test_termination_failure_fail_stop(
	const char *self,
	const char *pid_path)
{
	pid_t supervisor;
	pid_t descendant;
	pid_t waited;
	int descendant_status = 0;
	int supervisor_status = 0;
	char *pid_content;

	require(prctl(PR_SET_CHILD_SUBREAPER, 1) == 0,
		"enable test subreaper");
	supervisor = fork();
	require(supervisor >= 0, "fork containment supervisor");
	if (supervisor == 0) {
		char *empty_environment[] = { NULL };
		char *arguments[] = { (char *)self, "fixture", "orphan", NULL };
		struct spawn_posix_result result;

		wrapper_owner = getpid();
		fail_group_termination_once = 1;
		(void)spawn_posix_execute(
			self, arguments, 0, empty_environment, "/",
			SPAWN_POSIX_TRUNCATE_FILE, pid_path, 0, NULL, 1000,
			&result);
		_exit(96);
	}
	require(__real_waitpid(supervisor, &supervisor_status, 0) == supervisor,
		"wait for containment supervisor");
	pid_content = read_file(pid_path);
	descendant = (pid_t)strtol(pid_content, NULL, 10);
	free(pid_content);
	require(descendant > 0, "read fail-stop descendant pid");
	for (int attempt = 0; attempt < 100; ++attempt) {
		waited = __real_waitpid(descendant, &descendant_status, WNOHANG);
		if (waited != 0)
			break;
		struct timespec pause = { 0, 10 * 1000 * 1000 };
		(void)nanosleep(&pause, NULL);
	}
	if (waited == 0) {
		(void)__real_kill(descendant, SIGKILL);
		(void)__real_waitpid(descendant, &descendant_status, 0);
	}
	require(WIFEXITED(supervisor_status)
		&& WEXITSTATUS(supervisor_status) ==
			CONTAINMENT_EXIT_STATUS,
		"termination failure did not fail-stop supervisor");
	require(waited == descendant && WIFSIGNALED(descendant_status)
		&& WTERMSIG(descendant_status) == SIGKILL,
		"fail-stop did not kill the uncontained group");
	do {
		waited = __real_waitpid(-1, &descendant_status, 0);
	} while (waited > 0 || (waited < 0 && errno == EINTR));
	require(waited < 0 && errno == ECHILD,
		"fail-stop left an adopted child unreaped");
	pass("termination failure fail-stops group owner");
}

/* Prove an unexpected final leader-reap failure cannot resume the manager. */
static void test_reap_failure_fail_stop(void)
{
	pid_t supervisor;
	pid_t waited;
	int child_status;
	int supervisor_status;

	require(prctl(PR_SET_CHILD_SUBREAPER, 1) == 0,
		"enable reap-failure test subreaper");
	supervisor = fork();
	require(supervisor >= 0, "fork reap-failure supervisor");
	if (supervisor == 0) {
		char *empty_environment[] = { NULL };
		char *arguments[] = { "/missing", NULL };
		struct spawn_posix_result result;

		wrapper_owner = getpid();
		fail_waitpid_once = 1;
		(void)spawn_posix_execute(
			"/definitely/missing/spawn-target", arguments, 0,
			empty_environment, "/", 0, NULL, 0, NULL, -1, &result);
		_exit(96);
	}
	require(__real_waitpid(supervisor, &supervisor_status, 0) == supervisor,
		"wait for reap-failure supervisor");
	do {
		waited = __real_waitpid(-1, &child_status, 0);
	} while (waited > 0 || (waited < 0 && errno == EINTR));
	require(waited < 0 && errno == ECHILD,
		"reap failure left an adopted child unreaped");
	require(WIFEXITED(supervisor_status)
		&& WEXITSTATUS(supervisor_status) == CONTAINMENT_EXIT_STATUS,
		"reap failure did not fail-stop supervisor");
	pass("leader reap failure fail-stops group owner");
}

/* Prove a killed but unreapable leader cannot block manager cancellation. */
static void test_leader_reap_timeout_fail_stop(void)
{
	pid_t supervisor;
	pid_t adopted;
	int adopted_status;
	int supervisor_status;

	require(prctl(PR_SET_CHILD_SUBREAPER, 1) == 0,
		"enable leader-timeout test subreaper");
	supervisor = fork();
	require(supervisor >= 0, "fork leader-timeout supervisor");
	if (supervisor == 0) {
		char *empty_environment[] = { NULL };
		char *arguments[] = { "/bin/sleep", "60", NULL };
		struct spawn_posix_result result;

		wrapper_owner = getpid();
		stall_leader_reap = 1;
		(void)spawn_posix_execute(
			"/bin/sleep", arguments, 0, empty_environment, "/",
			0, NULL, 0, NULL, 10, &result);
		_exit(96);
	}
	require(__real_waitpid(supervisor, &supervisor_status, 0) == supervisor,
		"wait for leader-timeout supervisor");
	require(WIFEXITED(supervisor_status)
		&& WEXITSTATUS(supervisor_status) == CONTAINMENT_EXIT_STATUS,
		"leader reap timeout did not fail-stop group owner");
	do {
		adopted = __real_waitpid(-1, &adopted_status, 0);
	} while (adopted > 0 || (adopted < 0 && errno == EINTR));
	require(adopted < 0 && errno == ECHILD,
		"leader reap timeout left an adopted child");
	pass("leader reap timeout fail-stops without blocking cancellation");
}

/* Prove descendant-reap failure never retries a recycled process-group id. */
static void test_group_reap_failure_fail_stop(
	const char *self,
	const char *pid_path)
{
	int marker_pipe[2];
	pid_t supervisor;
	pid_t adopted;
	int adopted_status;
	int supervisor_status;
	char marker;
	ssize_t marker_count;

	require(pipe(marker_pipe) == 0, "create group-reap marker pipe");
	supervisor = fork();
	require(supervisor >= 0, "fork group-reap supervisor");
	if (supervisor == 0) {
		char *empty_environment[] = { NULL };
		char *arguments[] = { (char *)self, "fixture", "tree", NULL };
		struct spawn_posix_result result;

		(void)close(marker_pipe[0]);
		wrapper_owner = getpid();
		track_group_lifetime = 1;
		tracked_group = -1;
		tracked_leader_reaped = 0;
		group_signal_after_reap = 0;
		fail_group_reap_once = 1;
		lifecycle_marker_fd = marker_pipe[1];
		(void)spawn_posix_execute(
			self, arguments, 0, empty_environment, "/",
			SPAWN_POSIX_TRUNCATE_FILE, pid_path, 0, NULL, 50,
			&result);
		_exit(group_signal_after_reap ? 97 : 96);
	}
	require(close(marker_pipe[1]) == 0, "close group-reap marker writer");
	require(__real_waitpid(supervisor, &supervisor_status, 0) == supervisor,
		"wait for group-reap supervisor");
	marker_count = read(marker_pipe[0], &marker, sizeof(marker));
	require(close(marker_pipe[0]) == 0, "close group-reap marker reader");
	require(marker_count == 0,
		"group cleanup signaled a recycled identity after leader reap");
	require(WIFEXITED(supervisor_status)
		&& WEXITSTATUS(supervisor_status) == CONTAINMENT_EXIT_STATUS,
		"descendant reap failure did not fail-stop group owner");
	do {
		adopted = __real_waitpid(-1, &adopted_status, 0);
	} while (adopted > 0 || (adopted < 0 && errno == EINTR));
	require(adopted < 0 && errno == ECHILD,
		"descendant reap failure left an adopted child");
	pass("descendant reap failure retires group identity before fail-stop");
}

struct threaded_execution {
	const char *self;
	const char *fixture;
	const char *output_path;
	int return_code;
	struct spawn_posix_result result;
};

/* Execute one request in the same role as the manager's Ada main task. */
static void *run_threaded_execution(void *argument)
{
	struct threaded_execution *execution = argument;
	char *empty_environment[] = { NULL };
	char *arguments[] = {
		(char *)execution->self, "fixture",
		(char *)(execution->fixture != NULL ? execution->fixture : "tree"),
		NULL
	};

	execution->return_code = spawn_posix_execute(
		execution->self, arguments, 0, empty_environment, "/",
		execution->output_path != NULL ? SPAWN_POSIX_TRUNCATE_FILE : 0,
		execution->output_path,
		0, NULL, 1000, &execution->result);
	return NULL;
}

/* Model the GNAT interrupt-server task which invokes the C shutdown hook. */
static void *run_threaded_termination(void *argument)
{
	(void)argument;
	atomic_store(&termination_call_started, 1);
	spawn_posix_terminate_current();
	atomic_store(&termination_call_finished, 1);
	return NULL;
}

/* Exercise the publication race inside one disposable manager process. */
static void run_threaded_group_publication(const char *self)
{
	struct threaded_execution execution = { .self = self };
	pthread_t execution_thread;
	pthread_t termination_thread;
	struct timespec pause = { 0, 10 * 1000 * 1000 };

	wrapper_owner = getpid();
	atomic_store(&pause_parent_after_fork, 1);
	atomic_store(&parent_fork_paused, 0);
	atomic_store(&release_parent_fork, 0);
	atomic_store(&termination_call_started, 0);
	require(pthread_create(
		&execution_thread, NULL, run_threaded_execution, &execution) == 0,
		"create threaded execution");
	for (int attempt = 0;
	     attempt < 500 && !atomic_load(&parent_fork_paused);
	     ++attempt)
		(void)nanosleep(&pause, NULL);
	require(atomic_load(&parent_fork_paused),
		"threaded execution did not reach the fork barrier");
	require(pthread_create(
		&termination_thread, NULL, run_threaded_termination, NULL) == 0,
		"create threaded termination");
	for (int attempt = 0;
	     attempt < 500 && !atomic_load(&termination_call_started);
	     ++attempt)
		(void)nanosleep(&pause, NULL);
	require(atomic_load(&termination_call_started),
		"threaded termination did not start");
	for (int attempt = 0; attempt < 5; ++attempt)
		(void)nanosleep(&pause, NULL);
	atomic_store(&release_parent_fork, 1);
	require(pthread_join(termination_thread, NULL) == 0,
		"join threaded termination");
	require(pthread_join(execution_thread, NULL) == 0,
		"join threaded execution");
	wrapper_owner = -1;
	require(execution.return_code == 0
		&& execution.result.kind == SPAWN_POSIX_SIGNALED
		&& execution.result.signal_number == SIGKILL,
		"threaded shutdown missed the unpublished request group");
}

/* Prove shutdown cannot pass the fork-to-group-publication window. */
static void test_threaded_group_publication(const char *self)
{
	pid_t supervisor;
	int supervisor_status;

	supervisor = fork();
	require(supervisor >= 0, "fork threaded publication supervisor");
	if (supervisor == 0) {
		run_threaded_group_publication(self);
		_exit(0);
	}
	require(__real_waitpid(
		supervisor, &supervisor_status, 0) == supervisor,
		"wait for threaded publication supervisor");
	require(WIFEXITED(supervisor_status)
		&& WEXITSTATUS(supervisor_status) == 0,
		"threaded publication supervisor failed");
	pass("threaded shutdown waits for request-group publication");
}

/* Bound every test barrier so a broken acknowledgement cannot hang tests. */
static void wait_for_test_flag(atomic_int *flag, const char *message)
{
	struct timespec pause = { 0, 10 * 1000 * 1000 };

	for (int attempt = 0; attempt < 500 && !atomic_load(flag); ++attempt)
		(void)nanosleep(&pause, NULL);
	require(atomic_load(flag), message);
}

/* Hold the executor precisely between leader retirement and descendant reap. */
static void run_threaded_reaping(
	const char *self,
	const char *pid_path,
	int stall)
{
	struct threaded_execution execution = {
		.self = self, .fixture = "orphan", .output_path = pid_path
	};
	pthread_t executor;
	pthread_t terminator;
	struct timespec pause = { 0, 10 * 1000 * 1000 };
	char *contents;
	pid_t descendant;
	int returned_early;

	/* Alarm is recovery only; an exhausted production deadline exits 125. */
	alarm(5);
	wrapper_owner = getpid();
	atomic_store(&pause_group_reap_once, 1);
	atomic_store(&group_reap_paused, 0);
	atomic_store(&release_group_reap, 0);
	atomic_store(&termination_call_started, 0);
	atomic_store(&termination_call_finished, 0);
	require(pthread_create(
		&executor, NULL, run_threaded_execution, &execution) == 0,
		"start paused reaping executor");
	wait_for_test_flag(&group_reap_paused, "executor missed reap barrier");
	contents = read_file(pid_path);
	descendant = (pid_t)strtol(contents, NULL, 10);
	free(contents);
	require(descendant > 0 && kill(descendant, 0) == 0,
		"reaping fixture has no unreaped descendant");
	if (stall) {
		spawn_posix_terminate_current();
		_exit(96);
	}

	require(pthread_create(
		&terminator, NULL, run_threaded_termination, NULL) == 0,
		"start reaping termination task");
	wait_for_test_flag(&termination_call_started, "termination task missing");
	for (int attempt = 0;
	     attempt < 20 && !atomic_load(&termination_call_finished); ++attempt)
		(void)nanosleep(&pause, NULL);
	returned_early = atomic_load(&termination_call_finished);
	atomic_store(&release_group_reap, 1);
	require(pthread_join(terminator, NULL) == 0, "join reaping terminator");
	require(pthread_join(executor, NULL) == 0, "join reaping executor");
	require(!returned_early, "shutdown returned before descendant reaping");
	require(execution.return_code == 0,
		"paused reaping executor did not complete");
	require_exited(&execution.result, 0, "paused reaping result");
	(void)alarm(0);
}

/* Assert the post-retirement wait and its fail-stop bound in fresh managers. */
static void test_threaded_reaping(const char *self, const char *pid_path)
{
	for (int stall = 0; stall < 2; ++stall) {
		pid_t supervisor = fork();
		pid_t adopted;
		int status;
		int child_status;
		struct timespec pause = { 0, 10 * 1000 * 1000 };

		require(supervisor >= 0, "fork reaping supervisor");
		if (supervisor == 0) {
			run_threaded_reaping(self, pid_path, stall);
			_exit(0);
		}
		require(__real_waitpid(supervisor, &status, 0) == supervisor,
			"wait for reaping supervisor");
		/* A fail-stop can leave killed children; own and reap those here. */
		for (int attempt = 0; attempt < 500; ++attempt) {
			adopted = __real_waitpid(-1, &child_status, WNOHANG);
			if (adopted < 0 && errno == ECHILD)
				break;
			require(adopted >= 0 || errno == EINTR,
				"reaping supervisor recovery failed");
			(void)nanosleep(&pause, NULL);
		}
		require(adopted < 0 && errno == ECHILD,
			"reaping supervisor left an adopted child");
		require(WIFEXITED(status) && WEXITSTATUS(status)
			== (stall ? CONTAINMENT_EXIT_STATUS : 0),
			"shutdown reap acknowledgement or bound failed");
		pass(stall ? "stalled shutdown reaping fail-stops within its bound"
			: "shutdown waits beyond process-group identity retirement");
	}
}

static void test_timeout_group(
	const char *self,
	const char *pid_path)
{
	char *empty_environment[] = { NULL };
	char *arguments[] = { (char *)self, "fixture", "tree", NULL };
	struct spawn_posix_result result;
	char *pid_content;
	pid_t descendant;

	require(spawn_posix_execute(
		self, arguments, 0, empty_environment, "/",
		SPAWN_POSIX_TRUNCATE_FILE, pid_path, 0, NULL, 500, &result) == 0,
		"execute timeout fixture");
	require(result.kind == SPAWN_POSIX_TIMED_OUT, "classify timeout");
	pid_content = read_file(pid_path);
	descendant = (pid_t)strtol(pid_content, NULL, 10);
	free(pid_content);
	require(descendant > 0, "read descendant pid");
	require(kill(descendant, 0) < 0 && errno == ESRCH,
		"timeout descendant survived");
	pass("timeout kills and reaps request group");
}

static void test_success_group_cleanup(
	const char *self,
	const char *pid_path)
{
	char *empty_environment[] = { NULL };
	char *arguments[] = { (char *)self, "fixture", "orphan", NULL };
	struct spawn_posix_result result;
	char *pid_content;
	pid_t descendant;

	wrapper_owner = getpid();
	track_group_lifetime = 1;
	tracked_group = -1;
	tracked_leader_reaped = 0;
	group_signal_after_reap = 0;
	require(spawn_posix_execute(
		self, arguments, 0, empty_environment, "/",
		SPAWN_POSIX_TRUNCATE_FILE, pid_path, 0, NULL, 1000, &result) == 0,
		"execute successful orphan fixture");
	track_group_lifetime = 0;
	wrapper_owner = -1;
	require_exited(&result, 0, "preserve successful leader result");
	require(!group_signal_after_reap,
		"request group was signaled after leader reap");
	pid_content = read_file(pid_path);
	descendant = (pid_t)strtol(pid_content, NULL, 10);
	free(pid_content);
	require(descendant > 0, "read successful descendant pid");
	require(kill(descendant, 0) < 0 && errno == ESRCH,
		"successful descendant survived");
	pass("success kills and reaps remaining request group");
}

int main(int argc, char *argv[], char *envp[])
{
	char self[PATH_MAX];
	char cwd[PATH_MAX];
	char root[PATH_MAX];
	char stdout_path[PATH_MAX];
	char stderr_path[PATH_MAX];
	char symlink_path[PATH_MAX];
	char fifo_path[PATH_MAX];
	char pid_path[PATH_MAX];
	int source_fd;
	int inherited_fd;
	mode_t original_umask;

	if (argc == 2 && strcmp(argv[1], "--benchmark") == 0)
		return benchmark();
	if (argc == 3 && strcmp(argv[1], "sigchld-core") == 0)
		return fixture_inherited_sigchld(argv[0], argv[2]);
	if (argc > 1 && strcmp(argv[1], "fixture") == 0)
		return fixture(argc, argv, envp);
	original_umask = umask(0022);
	require(realpath(argv[0], self) != NULL, "resolve test executable");
	require(getcwd(cwd, sizeof(cwd)) != NULL, "get test cwd");
	require(snprintf(root, sizeof(root), "%s/obj/posix-core-test", cwd)
		< (int)sizeof(root), "construct test root");
	require(mkdir(root, 0700) == 0 || errno == EEXIST, "create test root");
	require(snprintf(stdout_path, sizeof(stdout_path), "%s/stdout", root)
		< (int)sizeof(stdout_path), "construct stdout path");
	require(snprintf(stderr_path, sizeof(stderr_path), "%s/stderr", root)
		< (int)sizeof(stderr_path), "construct stderr path");
	require(snprintf(symlink_path, sizeof(symlink_path), "%s/link", root)
		< (int)sizeof(symlink_path), "construct symlink path");
	require(snprintf(fifo_path, sizeof(fifo_path), "%s/signal-fifo", root)
		< (int)sizeof(fifo_path), "construct signal fifo path");
	require(snprintf(pid_path, sizeof(pid_path), "%s/pid", root)
		< (int)sizeof(pid_path), "construct pid path");
	(void)unlink(stdout_path);
	(void)unlink(stderr_path);
	(void)unlink(symlink_path);
	(void)unlink(fifo_path);
	(void)unlink(pid_path);
	test_inherited_sigchld_disposition(self);
	test_empty_descriptor_fallback();
	test_proc_scan_error_fallback(self);

	/*
	 * Model manager and GNU Make jobserver descriptors: all persistent
	 * descriptors exist before the first request and remain open in the
	 * manager while every target must close them.
	 */
	source_fd = open("/dev/null", O_RDONLY);
	require(source_fd >= 0, "open descriptor fixture");
	inherited_fd = fcntl(source_fd, F_DUPFD, 100);
	require(inherited_fd >= 100, "duplicate descriptor fixture");

	test_no_proc_descriptor_cleanup();
	test_pidfd_fallback();
	test_child_containment_state(self);
	test_exit_and_signal(self);
	test_error_pipe_duplication(self);
	test_exec_failure(self);
	test_termination_failure_fail_stop(self, pid_path);
	require(unlink(pid_path) == 0, "reset fail-stop pid file");
	test_reap_failure_fail_stop();
	test_leader_reap_timeout_fail_stop();
	test_group_reap_failure_fail_stop(self, pid_path);
	require(unlink(pid_path) == 0, "reset group-reap pid file");
	test_interrupted_group_setup_reap();
	test_group_setup_failure_descendants(self, pid_path);
	require(unlink(pid_path) == 0, "reset group setup descendant pid file");
	test_request_data(self, root, stdout_path, stderr_path);
	test_stdin_and_descriptors(self, inherited_fd);
	test_stream_nofollow(self, symlink_path);
	test_timeout_group(self, pid_path);
	require(unlink(pid_path) == 0, "reset descendant pid file");
	test_success_group_cleanup(self, pid_path);
	test_child_signal_dispositions(fifo_path);
	test_threaded_group_publication(self);
	test_threaded_reaping(self, pid_path);

	require(close(inherited_fd) == 0 && close(source_fd) == 0,
		"close descriptor fixture");
	require(unlink(stdout_path) == 0, "remove stdout");
	require(unlink(stderr_path) == 0, "remove stderr");
	require(unlink(pid_path) == 0, "remove pid file");
	require(rmdir(root) == 0, "remove test root");
	(void)umask(original_umask);
	printf("PASS POSIX core total: %u\n", passed);
	return 0;
}
