CC = gcc
AR = ar
BUILD ?= build
BASE_CFLAGS = -std=c17 -Wall -Wextra -Wpedantic -Werror -Wformat=2 -Wstrict-prototypes -Wmissing-prototypes
CFLAGS ?= $(BASE_CFLAGS) -O2 -g
CPPFLAGS += -D_GNU_SOURCE -Iinclude -Itests
LDFLAGS ?=
LDLIBS = -lcrypto

.PHONY: all check-toolchain test demo-assert sanitize package install
all: check-toolchain $(BUILD)/libicl.a $(BUILD)/icl-demo

check-toolchain:
	@test "$$($(CC) -dumpversion | cut -d. -f1)" = 14 || { echo 'GCC 14 is required' >&2; exit 1; }

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/icl.o: src/icl.c include/icl.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD)/libicl.a: $(BUILD)/icl.o
	$(AR) rcs $@ $^

$(BUILD)/oracle.o: tests/oracle.c tests/oracle.h include/icl.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD)/scenario.o: tests/scenario.c tests/scenario.h tests/oracle.h include/icl.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD)/main.o: src/main.c tests/scenario.h include/icl.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD)/test.o: tests/test.c tests/scenario.h tests/oracle.h include/icl.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD)/icl-demo: $(BUILD)/main.o $(BUILD)/scenario.o $(BUILD)/oracle.o $(BUILD)/libicl.a
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(BUILD)/icl-tests: $(BUILD)/test.o $(BUILD)/scenario.o $(BUILD)/oracle.o $(BUILD)/libicl.a
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

test: check-toolchain $(BUILD)/icl-tests
	$(BUILD)/icl-tests

demo-assert: all
	$(BUILD)/icl-demo
	$(BUILD)/icl-demo --json

sanitize: check-toolchain
	$(MAKE) BUILD=build/sanitize CFLAGS='$(BASE_CFLAGS) -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer' LDFLAGS='-fsanitize=address,undefined' build/sanitize/icl-tests
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 build/sanitize/icl-tests

PREFIX ?= $(HOME)/.local
DESTDIR ?=
install: all
	install -d $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/lib $(DESTDIR)$(PREFIX)/include
	install -d $(DESTDIR)$(PREFIX)/share/doc/inotify-convergence-lab
	install -m 755 $(BUILD)/icl-demo $(DESTDIR)$(PREFIX)/bin/icl-demo
	install -m 644 $(BUILD)/libicl.a $(DESTDIR)$(PREFIX)/lib/libicl.a
	install -m 644 include/icl.h $(DESTDIR)$(PREFIX)/include/icl.h
	install -m 644 LICENSE README.md README.pt-BR.md docs/contract.md $(DESTDIR)$(PREFIX)/share/doc/inotify-convergence-lab/

PACKAGE_FILES = Makefile Dockerfile include src tests docs README.md README.pt-BR.md CHANGELOG.md CONTRIBUTING.md SECURITY.md LICENSE .gitignore .dockerignore .editorconfig .github/workflows/ci.yml
package: | $(BUILD)
	tar -czf $(BUILD)/inotify-convergence-lab-0.1.0.tar.gz --transform='s,^,inotify-convergence-lab-0.1.0/,' $(PACKAGE_FILES)
