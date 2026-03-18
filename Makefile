.PHONY: all compile test dialyzer check release clean install uninstall tag

PREFIX ?= /opt/erlkoenig_elf
RELEASE_DIR = _build/prod/rel/erlkoenig_elf

# ── Build ────────────────────────────────────────────────

all: compile

compile:
	rebar3 compile

# ── Test ─────────────────────────────────────────────────

test:
	rebar3 eunit

dialyzer:
	rebar3 dialyzer

check: test dialyzer

# ── Release ──────────────────────────────────────────────

release: compile
	rebar3 as prod tar

# ── Install (local) ─────────────────────────────────────

install: release
	@echo "Installing to $(PREFIX) ..."
	mkdir -p $(PREFIX)
	tar xzf $(RELEASE_DIR)/erlkoenig_elf-*.tar.gz -C $(PREFIX)
	chown -R root:root $(PREFIX)
	chmod 755 $(PREFIX)/bin/erlkoenig_elf_run
	chmod 755 $(PREFIX)/bin/erlkoenig_elf_remsh
	chmod 644 $(PREFIX)/config/sys.config
	chmod 644 $(PREFIX)/config/vm.args
	chmod 644 $(PREFIX)/dist/erlkoenig_elf.service
	@# Cookie (first install only)
	@if [ ! -f $(PREFIX)/cookie ]; then \
		head -c 32 /dev/urandom | base64 | tr -d '/+=\n' | head -c 32 > $(PREFIX)/cookie; \
		echo "  Cookie generated"; \
	fi
	chmod 400 $(PREFIX)/cookie
	@# Systemd symlink
	@if [ -d /etc/systemd/system ]; then \
		ln -sf $(PREFIX)/dist/erlkoenig_elf.service /etc/systemd/system/erlkoenig_elf.service; \
		systemctl daemon-reload; \
		echo "  Systemd unit symlinked"; \
	fi
	@echo "Done. Start with: sudo systemctl start erlkoenig_elf"

uninstall:
	@echo "Uninstalling erlkoenig_elf ..."
	-systemctl stop erlkoenig_elf 2>/dev/null || true
	-systemctl disable erlkoenig_elf 2>/dev/null || true
	rm -f /etc/systemd/system/erlkoenig_elf.service
	-systemctl daemon-reload 2>/dev/null || true
	rm -rf $(PREFIX)
	@echo "Done."

# ── Version tag ──────────────────────────────────────────

tag:
ifndef VERSION
	$(error VERSION is required. Usage: make tag VERSION=0.1.0)
endif
	@if [ "$$(git branch --show-current)" != "main" ]; then \
		echo "Error: tags must be created from main branch" >&2; \
		exit 1; \
	fi
	@if [ -n "$$(git status --porcelain)" ]; then \
		echo "Error: working tree is not clean" >&2; \
		exit 1; \
	fi
	@echo "Tagging v$(VERSION) ..."
	sed -i 's/{vsn, "[^"]*"}/{vsn, "$(VERSION)"}/' src/erlkoenig_elf.app.src
	sed -i 's/{release, {erlkoenig_elf, "[^"]*"}/{release, {erlkoenig_elf, "$(VERSION)"}/' rebar.config
	git add src/erlkoenig_elf.app.src rebar.config
	git commit -m "Release v$(VERSION)"
	git tag -a "v$(VERSION)" -m "Release v$(VERSION)"
	@echo "Done. Push with: git push origin main v$(VERSION)"

# ── CI artifact download ────────────────────────────────

fetch-artifacts:
ifdef RUN_ID
	gh run download $(RUN_ID) -D /tmp/erlkoenig_elf-artifacts
else
	gh run download -D /tmp/erlkoenig_elf-artifacts
endif
	@echo "Artifacts in /tmp/erlkoenig_elf-artifacts/"
	@echo "Install with: sudo sh install.sh --local /tmp/erlkoenig_elf-artifacts"

# ── Syscall matrix tests ────────────────────────────────

test-matrix-gen:
	escript test/syscall_matrix/gen_asm.escript
	escript test/syscall_matrix/gen_go.escript

test-matrix-build:
	test/syscall_matrix/build_asm.sh
	-test/syscall_matrix/build_go.sh

test-matrix-strace:
	test/syscall_matrix/run_strace.sh

test-matrix: compile
	rebar3 eunit --module=elf_syscall_matrix_test

test-all: test test-matrix

# ── Clean ────────────────────────────────────────────────

clean:
	rebar3 clean
	rm -rf _build
