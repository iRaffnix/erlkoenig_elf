%%% @doc Syscall number/name mapping database for Linux.
%%%
%%% Provides bidirectional lookup between syscall numbers and names
%%% for x86_64 and aarch64 architectures, plus security-relevant
%%% category classification.
-module(elf_syscall_db).

-export([name/2, number/2, all/1, category/1]).

%% ---------------------------------------------------------------------------
%% API
%% ---------------------------------------------------------------------------

-spec name(x86_64 | aarch64, non_neg_integer()) -> {ok, binary()} | error.
name(Arch, Nr) ->
    case table(Arch) of
        error -> error;
        {ok, Tab} ->
            case maps:find(Nr, Tab) of
                {ok, _} = Ok -> Ok;
                error -> error
            end
    end.

-spec number(x86_64 | aarch64, binary()) -> {ok, non_neg_integer()} | error.
number(Arch, Name) ->
    case reverse_table(Arch) of
        error -> error;
        {ok, Tab} ->
            case maps:find(Name, Tab) of
                {ok, _} = Ok -> Ok;
                error -> error
            end
    end.

-spec all(x86_64 | aarch64) -> [{non_neg_integer(), binary()}].
all(Arch) ->
    case table(Arch) of
        error -> [];
        {ok, Tab} -> lists:sort(maps:to_list(Tab))
    end.

-spec category(binary()) -> network | filesystem | process | memory | ipc | time | signal | io | other.
category(Name) ->
    category_lookup(Name).

%% ---------------------------------------------------------------------------
%% Internal — table dispatch
%% ---------------------------------------------------------------------------

-spec table(x86_64 | aarch64) -> {ok, #{non_neg_integer() => binary()}} | error.
table(x86_64)  -> {ok, x86_64_table()};
table(aarch64) -> {ok, aarch64_table()};
table(_)       -> error.

-spec reverse_table(x86_64 | aarch64) -> {ok, #{binary() => non_neg_integer()}} | error.
reverse_table(Arch) ->
    case table(Arch) of
        error -> error;
        {ok, Tab} ->
            Rev = maps:fold(fun(Nr, Name, Acc) -> Acc#{Name => Nr} end, #{}, Tab),
            {ok, Rev}
    end.

%% ---------------------------------------------------------------------------
%% x86_64 syscall table
%% ---------------------------------------------------------------------------

x86_64_table() ->
    #{
        0   => <<"read">>,
        1   => <<"write">>,
        2   => <<"open">>,
        3   => <<"close">>,
        5   => <<"fstat">>,
        8   => <<"lseek">>,
        9   => <<"mmap">>,
        10  => <<"mprotect">>,
        11  => <<"munmap">>,
        12  => <<"brk">>,
        13  => <<"rt_sigaction">>,
        14  => <<"rt_sigprocmask">>,
        15  => <<"rt_sigreturn">>,
        16  => <<"ioctl">>,
        17  => <<"pread64">>,
        18  => <<"pwrite64">>,
        19  => <<"readv">>,
        20  => <<"writev">>,
        21  => <<"access">>,
        22  => <<"pipe">>,
        23  => <<"select">>,
        24  => <<"sched_yield">>,
        25  => <<"mremap">>,
        28  => <<"madvise">>,
        32  => <<"dup">>,
        33  => <<"dup2">>,
        35  => <<"nanosleep">>,
        37  => <<"alarm">>,
        39  => <<"getpid">>,
        40  => <<"sendfile">>,
        41  => <<"socket">>,
        42  => <<"connect">>,
        43  => <<"accept">>,
        44  => <<"sendto">>,
        45  => <<"recvfrom">>,
        46  => <<"sendmsg">>,
        47  => <<"recvmsg">>,
        48  => <<"shutdown">>,
        49  => <<"bind">>,
        50  => <<"listen">>,
        51  => <<"getsockname">>,
        52  => <<"getpeername">>,
        53  => <<"socketpair">>,
        54  => <<"setsockopt">>,
        55  => <<"getsockopt">>,
        56  => <<"clone">>,
        57  => <<"fork">>,
        58  => <<"vfork">>,
        59  => <<"execve">>,
        60  => <<"exit">>,
        61  => <<"wait4">>,
        62  => <<"kill">>,
        63  => <<"uname">>,
        72  => <<"fcntl">>,
        77  => <<"ftruncate">>,
        78  => <<"getdents">>,
        79  => <<"getcwd">>,
        80  => <<"chdir">>,
        82  => <<"rename">>,
        83  => <<"mkdir">>,
        84  => <<"rmdir">>,
        85  => <<"creat">>,
        86  => <<"link">>,
        87  => <<"unlink">>,
        88  => <<"symlink">>,
        89  => <<"readlink">>,
        90  => <<"chmod">>,
        91  => <<"fchmod">>,
        92  => <<"chown">>,
        96  => <<"gettimeofday">>,
        97  => <<"getrlimit">>,
        101 => <<"ptrace">>,
        102 => <<"getuid">>,
        104 => <<"getgid">>,
        110 => <<"getppid">>,
        131 => <<"sigaltstack">>,
        155 => <<"pivot_root">>,
        157 => <<"prctl">>,
        160 => <<"setrlimit">>,
        186 => <<"gettid">>,
        200 => <<"tkill">>,
        202 => <<"futex">>,
        217 => <<"getdents64">>,
        228 => <<"clock_gettime">>,
        231 => <<"exit_group">>,
        232 => <<"epoll_wait">>,
        233 => <<"epoll_ctl">>,
        257 => <<"openat">>,
        262 => <<"newfstatat">>,
        268 => <<"fchmodat">>,
        280 => <<"utimensat">>,
        281 => <<"epoll_pwait">>,
        288 => <<"accept4">>,
        290 => <<"eventfd2">>,
        291 => <<"epoll_create1">>,
        293 => <<"pipe2">>,
        302 => <<"prlimit64">>,
        318 => <<"getrandom">>,
        334 => <<"rseq">>,
        435 => <<"clone3">>,
        439 => <<"faccessat2">>,
        441 => <<"epoll_pwait2">>
    }.

%% ---------------------------------------------------------------------------
%% aarch64 syscall table
%% ---------------------------------------------------------------------------

aarch64_table() ->
    #{
        56  => <<"openat">>,
        57  => <<"close">>,
        63  => <<"read">>,
        64  => <<"write">>,
        66  => <<"writev">>,
        78  => <<"readlinkat">>,
        79  => <<"newfstatat">>,
        80  => <<"fstat">>,
        93  => <<"exit">>,
        94  => <<"exit_group">>,
        96  => <<"set_tid_address">>,
        98  => <<"futex">>,
        99  => <<"set_robust_list">>,
        113 => <<"clock_gettime">>,
        124 => <<"sched_yield">>,
        129 => <<"kill">>,
        134 => <<"rt_sigaction">>,
        135 => <<"rt_sigprocmask">>,
        136 => <<"rt_sigreturn">>,
        160 => <<"uname">>,
        169 => <<"gettimeofday">>,
        172 => <<"getpid">>,
        173 => <<"getppid">>,
        174 => <<"getuid">>,
        176 => <<"getgid">>,
        178 => <<"gettid">>,
        198 => <<"socket">>,
        200 => <<"bind">>,
        201 => <<"listen">>,
        202 => <<"connect">>,
        203 => <<"accept">>,
        204 => <<"getsockname">>,
        205 => <<"getpeername">>,
        206 => <<"sendto">>,
        207 => <<"recvfrom">>,
        208 => <<"setsockopt">>,
        209 => <<"getsockopt">>,
        210 => <<"shutdown">>,
        211 => <<"sendmsg">>,
        212 => <<"recvmsg">>,
        214 => <<"brk">>,
        215 => <<"munmap">>,
        216 => <<"mremap">>,
        220 => <<"clone">>,
        221 => <<"execve">>,
        222 => <<"mmap">>,
        226 => <<"mprotect">>,
        227 => <<"msync">>,
        233 => <<"madvise">>,
        261 => <<"prlimit64">>,
        278 => <<"getrandom">>,
        281 => <<"epoll_pwait">>,
        291 => <<"io_uring_enter">>,
        435 => <<"clone3">>
    }.

%% ---------------------------------------------------------------------------
%% Category classification
%% ---------------------------------------------------------------------------

-spec category_lookup(binary()) -> network | filesystem | process | memory | ipc | time | signal | io | other.
category_lookup(<<"socket">>)      -> network;
category_lookup(<<"connect">>)     -> network;
category_lookup(<<"accept">>)      -> network;
category_lookup(<<"accept4">>)     -> network;
category_lookup(<<"bind">>)        -> network;
category_lookup(<<"listen">>)      -> network;
category_lookup(<<"sendto">>)      -> network;
category_lookup(<<"recvfrom">>)    -> network;
category_lookup(<<"sendmsg">>)     -> network;
category_lookup(<<"recvmsg">>)     -> network;
category_lookup(<<"shutdown">>)    -> network;
category_lookup(<<"setsockopt">>)  -> network;
category_lookup(<<"getsockopt">>)  -> network;
category_lookup(<<"getsockname">>) -> network;
category_lookup(<<"getpeername">>) -> network;
category_lookup(<<"socketpair">>)  -> network;
category_lookup(<<"sendfile">>)    -> network;

category_lookup(<<"open">>)        -> filesystem;
category_lookup(<<"openat">>)      -> filesystem;
category_lookup(<<"read">>)        -> filesystem;
category_lookup(<<"write">>)       -> filesystem;
category_lookup(<<"close">>)       -> filesystem;
category_lookup(<<"fstat">>)       -> filesystem;
category_lookup(<<"newfstatat">>)  -> filesystem;
category_lookup(<<"lseek">>)       -> filesystem;
category_lookup(<<"access">>)      -> filesystem;
category_lookup(<<"faccessat2">>)  -> filesystem;
category_lookup(<<"rename">>)      -> filesystem;
category_lookup(<<"mkdir">>)       -> filesystem;
category_lookup(<<"rmdir">>)       -> filesystem;
category_lookup(<<"unlink">>)      -> filesystem;
category_lookup(<<"link">>)        -> filesystem;
category_lookup(<<"symlink">>)     -> filesystem;
category_lookup(<<"readlink">>)    -> filesystem;
category_lookup(<<"readlinkat">>)  -> filesystem;
category_lookup(<<"chmod">>)       -> filesystem;
category_lookup(<<"fchmod">>)      -> filesystem;
category_lookup(<<"fchmodat">>)    -> filesystem;
category_lookup(<<"chown">>)       -> filesystem;
category_lookup(<<"chdir">>)       -> filesystem;
category_lookup(<<"getcwd">>)      -> filesystem;
category_lookup(<<"creat">>)       -> filesystem;
category_lookup(<<"ftruncate">>)   -> filesystem;
category_lookup(<<"getdents">>)    -> filesystem;
category_lookup(<<"getdents64">>)  -> filesystem;
category_lookup(<<"fcntl">>)       -> filesystem;
category_lookup(<<"readv">>)       -> filesystem;
category_lookup(<<"writev">>)      -> filesystem;
category_lookup(<<"pread64">>)     -> filesystem;
category_lookup(<<"pwrite64">>)    -> filesystem;
category_lookup(<<"utimensat">>)   -> filesystem;
category_lookup(<<"pivot_root">>)  -> filesystem;
category_lookup(<<"ioctl">>)       -> filesystem;
category_lookup(<<"dup">>)         -> filesystem;
category_lookup(<<"dup2">>)        -> filesystem;

category_lookup(<<"clone">>)       -> process;
category_lookup(<<"clone3">>)      -> process;
category_lookup(<<"fork">>)        -> process;
category_lookup(<<"vfork">>)       -> process;
category_lookup(<<"execve">>)      -> process;
category_lookup(<<"exit">>)        -> process;
category_lookup(<<"exit_group">>)  -> process;
category_lookup(<<"wait4">>)       -> process;
category_lookup(<<"prctl">>)       -> process;
category_lookup(<<"ptrace">>)      -> process;
category_lookup(<<"getpid">>)      -> process;
category_lookup(<<"getppid">>)     -> process;
category_lookup(<<"getuid">>)      -> process;
category_lookup(<<"getgid">>)      -> process;
category_lookup(<<"gettid">>)      -> process;
category_lookup(<<"uname">>)       -> process;
category_lookup(<<"getrlimit">>)   -> process;
category_lookup(<<"setrlimit">>)   -> process;
category_lookup(<<"prlimit64">>)   -> process;
category_lookup(<<"rseq">>)        -> process;
category_lookup(<<"set_tid_address">>) -> process;
category_lookup(<<"set_robust_list">>) -> process;
category_lookup(<<"sched_yield">>) -> process;
category_lookup(<<"getrandom">>)   -> process;

category_lookup(<<"mmap">>)        -> memory;
category_lookup(<<"munmap">>)      -> memory;
category_lookup(<<"mprotect">>)    -> memory;
category_lookup(<<"brk">>)         -> memory;
category_lookup(<<"madvise">>)     -> memory;
category_lookup(<<"mremap">>)      -> memory;
category_lookup(<<"msync">>)       -> memory;

category_lookup(<<"pipe">>)        -> ipc;
category_lookup(<<"pipe2">>)       -> ipc;
category_lookup(<<"futex">>)       -> ipc;
category_lookup(<<"eventfd2">>)    -> ipc;

category_lookup(<<"rt_sigaction">>)   -> signal;
category_lookup(<<"rt_sigprocmask">>) -> signal;
category_lookup(<<"rt_sigreturn">>)   -> signal;
category_lookup(<<"sigaltstack">>)    -> signal;
category_lookup(<<"kill">>)           -> signal;
category_lookup(<<"tkill">>)          -> signal;
category_lookup(<<"alarm">>)          -> signal;

category_lookup(<<"clock_gettime">>)  -> time;
category_lookup(<<"nanosleep">>)      -> time;
category_lookup(<<"gettimeofday">>)   -> time;

category_lookup(<<"epoll_wait">>)     -> io;
category_lookup(<<"epoll_pwait">>)    -> io;
category_lookup(<<"epoll_pwait2">>)   -> io;
category_lookup(<<"epoll_ctl">>)      -> io;
category_lookup(<<"epoll_create1">>)  -> io;
category_lookup(<<"select">>)         -> io;
category_lookup(<<"io_uring_enter">>) -> io;

category_lookup(_)                    -> other.
