# erlkoenig_elf Usage

## CLI

```bash
erlkoenig-elf <command> [args]
```

Kurzform wenn `/opt/erlkoenig_elf/bin` im PATH, sonst voller Pfad:
`/opt/erlkoenig_elf/bin/erlkoenig-elf`

Kommuniziert mit dem Daemon via Unix Socket. Fallback auf lokale Analyse
wenn der Daemon offline ist.

### Befehle

```bash
# Vollanalyse (JSON)
erlkoenig-elf analyze /usr/bin/ls

# Syscalls extrahieren
erlkoenig-elf syscalls /path/to/binary

# Seccomp-Profil generieren (Docker/OCI-kompatibel)
erlkoenig-elf seccomp /path/to/binary

# Sprache erkennen (go, rust, zig, c, cpp, unknown)
erlkoenig-elf language /path/to/binary

# Eingebettete Dependencies (Go-Module, Rust-Crates)
erlkoenig-elf deps /path/to/binary

# Funktion neutralisieren (legt automatisch .orig-Backup an)
erlkoenig-elf patch /path/to/binary functionName
erlkoenig-elf patch /path/to/binary functionName --strategy ret_neg

# Daemon-Status
erlkoenig-elf ping         # → pong
erlkoenig-elf version      # → 0.2.0
erlkoenig-elf help
```

Alle Befehle geben JSON aus. Zum Formatieren: `| jq .`

### Patch-Strategien

| Strategie | Effekt |
|-----------|--------|
| `ret_zero` (default) | Return 0/nil/false |
| `ret_one` | Return 1 |
| `ret_neg` | Return -1/EINVAL |
| `nop` | NOP-Padding |

### Beispiele

```bash
# Go-Binary analysieren, Syscall-Kategorien anzeigen
erlkoenig-elf analyze /opt/myapp | jq '.syscalls.categories'

# Seccomp-Profil erzeugen und in Docker verwenden
erlkoenig-elf seccomp /opt/myapp > seccomp.json
docker run --security-opt seccomp=seccomp.json myimage

# Dependencies eines Go-Binaries auflisten
erlkoenig-elf deps /opt/myapp | jq '.[].path'

# Crypto-Funktion deaktivieren
erlkoenig-elf patch /opt/myapp 'crypto/sha256.Sum256' --strategy ret_zero
# Backup: /opt/myapp.orig
```

---

## Erlang API

Für programmatische Nutzung als Library oder in der Remote Shell.

### Parse

```erlang
{ok, Elf} = erlkoenig_elf:parse("/usr/bin/ls").
%% Auch mit Raw-Binary: erlkoenig_elf:parse(ElfBinary).
```

### Analyse

```erlang
{ok, Report} = erlkoenig_elf:analyze(Elf).
%% Report: #{arch, type, is_static, is_pie, has_debug, language,
%%           entry_point, sections, text_size, total_size,
%%           syscalls, language_info}
```

### Syscalls

```erlang
{ok, Info} = erlkoenig_elf:syscalls(Elf).
%% Info: #{arch, resolved => #{Nr => Name}, unresolved_count,
%%         sites => [...], categories => #{cat => [names]}}

{ok, Names} = erlkoenig_elf:syscall_names(Elf).
%% Names: [<<"read">>, <<"write">>, <<"exit_group">>]
```

### Seccomp

```erlang
{ok, Json} = erlkoenig_elf:seccomp_json(Elf).   %% Docker/OCI JSON
{ok, Bpf}  = erlkoenig_elf:seccomp_bpf(Elf).    %% Raw BPF bytecode
{ok, Prof} = erlkoenig_elf:seccomp_profile(Elf). %% Erlang-Record
```

### Sprache & Dependencies

```erlang
go = erlkoenig_elf:language(Elf).

{ok, GoInfo}   = erlkoenig_elf:go_info(Elf).    %% #go_info{version, main_module, deps, ...}
{ok, RustInfo} = erlkoenig_elf:rust_info(Elf).   %% #rust_info{crates, compiler}

{ok, Deps} = erlkoenig_elf:deps(Elf).            %% [#go_dep{} | #rust_crate{}]
{ok, Caps} = erlkoenig_elf:dep_capabilities(Elf). %% #{Dep => [Categories]}
Anomalies  = erlkoenig_elf:dep_anomalies(Elf).    %% Verdaechtige Capabilities
```

### Patching

```erlang
{ok, Info} = erlkoenig_elf:patch(Path, <<"funcName">>, ret_zero).
%% Info: #{function, addr, size, strategy, backup}

%% Fuer gestrippte Binaries: direkt per Adresse
{ok, Info} = erlkoenig_elf:patch_at(Path, 16#401000, 48, nop).
```

---

## Remote Shell

```bash
RELX_COOKIE=$(cat /opt/erlkoenig_elf/cookie) \
  /opt/erlkoenig_elf/bin/erlkoenig_elf remote_console
```

Beenden: `Ctrl+C Ctrl+C` (nicht `q().` — das stoppt den Node).

### erl_call (nicht-interaktiv)

```bash
/opt/erlkoenig_elf/erts-*/bin/erl_call \
  -sname erlkoenig_elf \
  -c $(cat /opt/erlkoenig_elf/cookie) \
  -a "erlkoenig_elf analyze [<<\"/usr/bin/ls\">>]"
```

---

## Unix Socket (eigene Clients)

Socket: `/run/erlkoenig_elf/ctl.sock` (override: `ERLKOENIG_ELF_SOCKET` env var)

Protokoll: 4-Byte Big-Endian Length-Prefix + Erlang ETF (`term_to_binary`/`binary_to_term`)

### Requests

```erlang
ping                                          → pong
version                                       → {version, <<"0.2.0">>}
{analyze, <<"/path/to/bin">>}                 → {ok, Map}
{syscalls, <<"/path/to/bin">>}                → {ok, Map}
{seccomp, <<"/path/to/bin">>}                 → {ok, JsonIodata}
{seccomp, <<"/path/to/bin">>, bpf}           → {ok, BpfBinary}
{language, <<"/path/to/bin">>}                → {ok, Atom}
{deps, <<"/path/to/bin">>}                    → {ok, List}
{patch, Path, FuncName, Strategy}             → {ok, Map}
```

### Errors

```erlang
{error, {file_not_found, Path}}
{error, {permission_denied, Path}}
{error, {not_regular_file, Path}}
{error, {internal, Reason}}
{error, unknown_request}
```

### Beispiel (Erlang-Client)

```erlang
{ok, S} = gen_tcp:connect({local, "/run/erlkoenig_elf/ctl.sock"}, 0,
                          [binary, {packet, 4}, {active, false}], 2000),
ok = gen_tcp:send(S, term_to_binary({analyze, <<"/usr/bin/ls">>})),
{ok, Data} = gen_tcp:recv(S, 0, 30000),
{ok, Result} = binary_to_term(Data),
gen_tcp:close(S).
```

---

## Output-Formate

### analyze

```json
{
  "arch": "x86_64",
  "type": "exec",
  "is_static": true,
  "is_pie": false,
  "has_debug": false,
  "language": "go",
  "entry_point": 4194304,
  "text_size": 1048576,
  "total_size": 5242880,
  "sections": [".text", ".rodata", ".gopclntab"],
  "syscalls": {
    "resolved": {"1": "write", "4": "stat"},
    "unresolved_count": 0,
    "categories": {"network": ["connect"], "filesystem": ["open", "read"]}
  },
  "language_info": {"version": "go1.22.1", "main_module": "github.com/user/app"}
}
```

### seccomp

```json
{
  "defaultAction": "SCMP_ACT_KILL_PROCESS",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [{"names": ["read", "write", "stat"], "action": "SCMP_ACT_ALLOW"}]
}
```

### deps (Go)

```json
[{"path": "github.com/lib/pq", "version": "v1.10.9", "hash": "h1:abc..."}]
```

### deps (Rust)

```json
[{"name": "tokio", "version": "1.35.0", "source": "panic_strings"}]
```

### patch

```json
{"function": "crypto/sha256.Sum256", "addr": 4197504, "size": 48, "strategy": "ret_zero", "backup": "/path.orig"}
```

---

## Unterstutzte Architekturen

- **x86-64**: Syscall-Erkennung via `MOV EAX/RAX, imm32; SYSCALL`
- **AArch64**: Syscall-Erkennung via `MOV X8/W8, imm; SVC #0`

## Unterstutzte Sprachen

| Sprache | Erkennung |
|---------|-----------|
| Go | `.gopclntab`, `.go.buildinfo` |
| Rust | v0-Demangling (`_R`-Prefix), Panic-Strings |
| Zig | DWARF Compiler-Info, Symbole |
| C/C++ | DWARF Debug-Info |

## Service-Management

Zwei Binaries: `erlkoenig-elf` (CLI, mit Bindestrich) und `erlkoenig_elf`
(relx-Wrapper, mit Unterstrich). Nicht verwechseln.

| Binary | Zweck |
|--------|-------|
| `erlkoenig-elf` | CLI: analyze, syscalls, seccomp, ... |
| `/opt/erlkoenig_elf/bin/erlkoenig_elf` | Daemon-Steuerung: foreground, remote_console, stop, ping |

```bash
# Dienst starten/stoppen
systemctl start erlkoenig_elf
systemctl stop erlkoenig_elf
systemctl restart erlkoenig_elf
systemctl status erlkoenig_elf
journalctl -u erlkoenig_elf -f

# Remote Shell (interaktiv, Beenden: Ctrl+C Ctrl+C — NICHT q().!)
RELX_COOKIE=$(cat /opt/erlkoenig_elf/cookie) \
  /opt/erlkoenig_elf/bin/erlkoenig_elf remote_console
```

**Hinweis:** Der Daemon laeuft mit `PrivateTmp=yes`. Dateien unter `/tmp`
sind fuer den Daemon nicht sichtbar. Binaries zum Analysieren z.B. unter
`/var/lib/erlkoenig_elf/` oder `/home/` ablegen.
