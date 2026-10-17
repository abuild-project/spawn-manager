PREFIX ?= $(HOME)/ada

SRCDIR = src
LIBDIR = lib
OBJDIR = obj
COVDIR = $(OBJDIR)/cov
POSIX_TEST = $(OBJDIR)/spawn_posix_tests
POSIX_TEST_LDFLAGS = -Wl,--wrap=kill -Wl,--wrap=opendir \
	-Wl,--wrap=readdir \
	-Wl,--wrap=fork -Wl,--wrap=setpgid -Wl,--wrap=syscall \
	-Wl,--wrap=waitpid -pthread
PROTOCOL_FAILURE_MANAGER = $(OBJDIR)/protocol_failure_manager

VERSION_SPEC := src/spawn-version.ads
VERSION       = $(shell cat .version | sed 's/^v//')
GIT_REV      := $(shell git describe --always 2> /dev/null)

GPR_FILE = gnat/spawn.gpr

BUILD_TYPE = prod

all: spawn_lib spawn_manager

.version: FORCE
	@if [ -d .git -o -f .git ]; then \
		if [ -r $@ ]; then \
			if [ "$$(cat $@)" != "$(GIT_REV)" ]; then \
				echo $(GIT_REV) > $@; \
			fi; \
		else \
			echo $(GIT_REV) > $@; \
		fi \
	fi

$(VERSION_SPEC): .version
	@echo "package Spawn.Version is"                > $@
	@echo "   Version_String : constant String :=" >> $@
	@echo "     \"$(VERSION)\";"                   >> $@
	@echo "end Spawn.Version;"                     >> $@

$(POSIX_TEST): tests/spawn-posix-tests.c src/spawn-posix.c src/spawn-posix.h
	@mkdir -p $(OBJDIR)
	$(CC) -std=c11 -W -Wall -Wextra -Werror -O2 -pthread -Isrc \
		$(POSIX_TEST_LDFLAGS) -o $@ \
		tests/spawn-posix-tests.c src/spawn-posix.c

$(PROTOCOL_FAILURE_MANAGER): tests/protocol-failure-manager.c
	@mkdir -p $(OBJDIR)
	$(CC) -std=c11 -W -Wall -Wextra -Werror -O2 -o $@ $<

spawn_tests:
	@gnatmake -P$@ -p

tests: $(POSIX_TEST) $(PROTOCOL_FAILURE_MANAGER) spawn_tests spawn_manager
	@$(POSIX_TEST)
	@$(OBJDIR)/spawn_manager 8192 $(OBJDIR)/spawn_manager_0 &
	@$(OBJDIR)/spawn_manager 30 $(OBJDIR)/spawn_manager_min_request &
	@$(OBJDIR)/spawn_manager 30 $(OBJDIR)/spawn_manager_min_protocol &
	@$(OBJDIR)/spawn_manager 47 $(OBJDIR)/spawn_manager_min_spawn &
	@$(OBJDIR)/test_runner
	@tests/check_signal_shutdown.sh "$(CURDIR)"
	@python3 tests/check_signal_reaping.py "$(abspath $(OBJDIR))/spawn_manager" 1
	@tests/check_adaflags.sh "$(CURDIR)"
	@tests/check_install.sh "$(CURDIR)"

spawn_manager: $(VERSION_SPEC)
	@gnatmake -P$@ -p -XBUILD=$(BUILD_TYPE)

spawn_performance:
	@gnatmake -P$@ -p

spawn_lib:
	@gnatmake -P$@ -p

perf: $(POSIX_TEST) spawn_performance spawn_manager
	@$(OBJDIR)/perf/performance
	@$(POSIX_TEST) --benchmark

install: install_lib install_manager

install_lib: spawn_lib
	install -d $(PREFIX)/include/spawn
	install -d $(PREFIX)/lib/spawn
	install -d $(PREFIX)/lib/gnat
	install -m 644 $(SRCDIR)/*.ad[bs] $(PREFIX)/include/spawn
	install -m 444 $(LIBDIR)/*.ali $(PREFIX)/lib/spawn
	install -m 444 $(LIBDIR)/libspawn.a $(PREFIX)/lib
	install -m 644 $(GPR_FILE) $(PREFIX)/lib/gnat

install_manager: spawn_manager
	rm -f $(PREFIX)/spawn_wrapper
	install -m 755 $(OBJDIR)/spawn_manager $(PREFIX)

cov: $(POSIX_TEST) $(PROTOCOL_FAILURE_MANAGER) spawn_manager
	@rm -f $(COVDIR)/*.gcda
	@gnatmake -Pspawn_tests.gpr -p -XBUILD="coverage"
	@$(OBJDIR)/spawn_manager 8192 $(OBJDIR)/spawn_manager_0 &
	@$(OBJDIR)/spawn_manager 30 $(OBJDIR)/spawn_manager_min_request &
	@$(OBJDIR)/spawn_manager 30 $(OBJDIR)/spawn_manager_min_protocol &
	@$(OBJDIR)/spawn_manager 47 $(OBJDIR)/spawn_manager_min_spawn &
	@$(COVDIR)/test_runner
	@lcov --ignore-errors inconsistent -c -d $(COVDIR) \
		-o $(COVDIR)/cov.info
	@lcov -e $(COVDIR)/cov.info "$(PWD)/src/*.adb" -o $(COVDIR)/cov.info
	@genhtml --no-branch-coverage $(COVDIR)/cov.info -o $(COVDIR)

doc:
	@$(MAKE) -C doc

clean:
	@rm -rf $(OBJDIR)
	@rm -rf $(LIBDIR)
	@$(MAKE) -C doc clean

FORCE:

.PHONY: doc perf tests
