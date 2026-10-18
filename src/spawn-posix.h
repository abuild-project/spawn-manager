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
 *
 * As a special exception, if other files instantiate generics from this unit,
 * or you link this unit with other files to produce an executable, this unit
 * does not by itself cause the resulting executable to be covered by the GNU
 * General Public License. This exception does not invalidate any other reason
 * why the executable might be covered by the GNU Public License.
 */

#ifndef SPAWN_POSIX_H
#define SPAWN_POSIX_H

#include <stdint.h>

/* Stable result values shared with the explicit Ada/C translation. */
enum spawn_posix_result_kind {
	SPAWN_POSIX_EXITED = 0,
	SPAWN_POSIX_SIGNALED = 1,
	SPAWN_POSIX_TIMED_OUT = 2,
	SPAWN_POSIX_SPAWN_FAILED = 3,
	SPAWN_POSIX_INTERNAL_ERROR = 4
};

/* Stable failure stages; keep these values aligned with the Ada mapping. */
enum spawn_posix_failure_stage {
	SPAWN_POSIX_NO_FAILURE = 0,
	SPAWN_POSIX_ENABLE_SUBREAPER = 1,
	SPAWN_POSIX_CREATE_ERROR_PIPE = 2,
	SPAWN_POSIX_FORK = 3,
	SPAWN_POSIX_PROCESS_GROUP = 4,
	SPAWN_POSIX_PARENT_DEATH = 5,
	SPAWN_POSIX_OPEN_STDIN = 6,
	SPAWN_POSIX_OPEN_STDOUT = 7,
	SPAWN_POSIX_OPEN_STDERR = 8,
	SPAWN_POSIX_DUP_STDIN = 9,
	SPAWN_POSIX_DUP_STDOUT = 10,
	SPAWN_POSIX_DUP_STDERR = 11,
	SPAWN_POSIX_CHANGE_DIRECTORY = 12,
	SPAWN_POSIX_RESET_SIGNALS = 13,
	SPAWN_POSIX_CLOSE_DESCRIPTORS = 14,
	SPAWN_POSIX_EXEC = 15,
	SPAWN_POSIX_WAIT = 16,
	SPAWN_POSIX_TERMINATE_GROUP = 17
};

/* Output policies; MERGE_STDOUT is valid only for stderr. */
enum spawn_posix_stream_mode {
	SPAWN_POSIX_NULL_STREAM = 0,
	SPAWN_POSIX_TRUNCATE_FILE = 1,
	SPAWN_POSIX_MERGE_STDOUT = 2
};

/* Complete result written on every return from spawn_posix_execute. */
struct spawn_posix_result {
	int kind;
	int exit_status;
	int signal_number;
	int failure_stage;
	int error_number;
};

/*
 * Execute one fully constructed launch request.
 *
 * argv includes argv[0] and ends with NULL. When inherit_environment is
 * nonzero, envp is ignored and the immutable manager environment is inherited.
 * Otherwise envp describes the complete replacement environment and ends with
 * NULL. A timeout of -1 waits indefinitely. The return value is zero for every
 * classified child or spawn result and -1 only when result describes an
 * internal supervision failure.
 */
int spawn_posix_execute(
	const char *executable,
	char *const argv[],
	int inherit_environment,
	char *const envp[],
	const char *directory,
	int stdout_mode,
	const char *stdout_path,
	int stderr_mode,
	const char *stderr_path,
	int64_t timeout_ms,
	struct spawn_posix_result *result);

/*
 * Kill the active request group, if any, and await its executor's final reap.
 *
 * This function is called by GNAT's SIGINT/SIGTERM interrupt-server task. It
 * synchronizes through a process-local mutex with fork publication and exact
 * leader reaping; it is not a raw POSIX signal handler. The normal execute path
 * remains the sole reaper, including descendants after leader retirement.
 * A stalled executor fail-stops the manager after a one-second reap wait.
 */
void spawn_posix_terminate_current(void);

#endif
