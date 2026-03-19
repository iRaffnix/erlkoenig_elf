.PHONY: all compile test dialyzer check release clean install uninstall tag

PREFIX ?= /opt/erlkoenig_elf
SERVICE_USER ?= erlkoenig
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
	@# Service user (idempotent)
	id -u $(SERVICE_USER) >/dev/null 2>&1 || \
		useradd --system --no-create-home --shell /usr/sbin/nologin $(SERVICE_USER)
	@# Extract release
	mkdir -p $(PREFIX)
	tar xzf $(RELEASE_DIR)/erlkoenig_elf-*.tar.gz -C $(PREFIX)
	@# Ownership: root owns files, service user can read
	chown -R root:$(SERVICE_USER) $(PREFIX)
	chmod 750 $(PREFIX)
	chmod 755 $(PREFIX)/bin/erlkoenig_elf
	@[ -f $(PREFIX)/bin/erlkoenig-elf ] && chmod 755 $(PREFIX)/bin/erlkoenig-elf || true
	chmod 644 $(PREFIX)/dist/erlkoenig_elf.service
	@# releases/0.1.0 must be writable — relx generates vm.args from vm.args.src at start
	@REL_VSN_DIR=$$(ls -d $(PREFIX)/releases/*/start.boot 2>/dev/null | head -1 | xargs dirname 2>/dev/null); \
	if [ -n "$$REL_VSN_DIR" ]; then \
		chown $(SERVICE_USER):$(SERVICE_USER) "$$REL_VSN_DIR"; \
		chmod 750 "$$REL_VSN_DIR"; \
	fi
	@# Cookie (first install only)
	@if [ ! -f $(PREFIX)/cookie ]; then \
		head -c 32 /dev/urandom | base64 | tr -d '/+=\n' | head -c 32 > $(PREFIX)/cookie; \
		echo "  Cookie generated"; \
	fi
	chown root:$(SERVICE_USER) $(PREFIX)/cookie
	chmod 440 $(PREFIX)/cookie
	@# Fix escript shebang to use bundled ERTS
	@ERTS_BIN=$$(ls -d $(PREFIX)/erts-*/bin 2>/dev/null | head -1); \
	if [ -n "$$ERTS_BIN" ] && [ -f $(PREFIX)/bin/erlkoenig-elf ]; then \
		sed -i "1s|.*|#!$$ERTS_BIN/escript|" $(PREFIX)/bin/erlkoenig-elf; \
		echo "  CLI shebang: $$ERTS_BIN/escript"; \
	fi
	@# Systemd symlink
	@if [ -d /etc/systemd/system ]; then \
		ln -sf $(PREFIX)/dist/erlkoenig_elf.service /etc/systemd/system/erlkoenig_elf.service; \
		systemctl daemon-reload; \
		echo "  Systemd unit symlinked"; \
	fi
	@# Hostname check
	@if ! getent hosts "$$(hostname -s)" >/dev/null 2>&1; then \
		echo ""; \
		echo "  WARNING: hostname '$$(hostname -s)' not resolvable."; \
		echo "  Add to /etc/hosts: 127.0.0.1 $$(hostname -s)"; \
		echo "  Distribution will not work without this."; \
		echo ""; \
	fi
	@echo ""
	@echo "Done. Next steps:"
	@echo "  1. Verify hostname:  getent hosts $$(hostname -s)"
	@echo "  2. Test foreground:  sudo -u $(SERVICE_USER) RELX_COOKIE=\$$(cat $(PREFIX)/cookie) $(PREFIX)/bin/erlkoenig_elf foreground"
	@echo "  3. Start service:    sudo systemctl start erlkoenig_elf"

uninstall:
	@echo "Uninstalling erlkoenig_elf ..."
	-systemctl stop erlkoenig_elf 2>/dev/null || true
	-systemctl disable erlkoenig_elf 2>/dev/null || true
	rm -f /etc/systemd/system/erlkoenig_elf.service
	-systemctl daemon-reload 2>/dev/null || true
	rm -rf $(PREFIX)
	@echo "Done. Note: User '$(SERVICE_USER)' not removed. Run: userdel $(SERVICE_USER)"

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
