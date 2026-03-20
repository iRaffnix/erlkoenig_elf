%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%

-module(erlkoenig_elf_srv).
-moduledoc """
ELF analysis service -- listens on a Unix socket, handles requests.

Protocol: 4-byte big-endian length prefix + ETF payload.
Requests/responses are Erlang terms via term_to_binary/binary_to_term.
""".
-behaviour(gen_server).

-export([start_link/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-record(state, {
    socket_path :: string(),
    listen_sock :: gen_tcp:socket() | undefined
}).

%% ---------------------------------------------------------------------------
%% API
%% ---------------------------------------------------------------------------

start_link(SocketPath) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, SocketPath, []).

%% ---------------------------------------------------------------------------
%% gen_server callbacks
%% ---------------------------------------------------------------------------

init(SocketPath) ->
    process_flag(trap_exit, true),
    proc_lib:set_label(erlkoenig_elf_srv),
    %% Remove stale socket file
    _ = file:delete(SocketPath),
    case
        gen_tcp:listen(0, [
            binary,
            {packet, 4},
            {active, false},
            {ifaddr, {local, SocketPath}},
            {backlog, 16}
        ])
    of
        {ok, LSock} ->
            %% Set socket permissions: 660 (owner + group only)
            _ = file:change_mode(SocketPath, 8#660),
            logger:notice("erlkoenig_elf_srv listening on ~s", [SocketPath]),
            self() ! accept,
            {ok, #state{socket_path = SocketPath, listen_sock = LSock}};
        {error, Reason} ->
            {stop, {listen_failed, Reason}}
    end.

handle_call(_Msg, _From, State) ->
    {reply, {error, not_implemented}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(accept, #state{listen_sock = LSock} = State) ->
    %% Spawn acceptor — non-blocking accept loop
    Self = self(),
    spawn_link(fun() -> accept_loop(Self, LSock) end),
    {noreply, State};
handle_info({client, Sock}, State) ->
    %% New client connected — spawn handler, then continue accepting
    spawn(fun() -> handle_client(Sock) end),
    {noreply, State};
handle_info({'EXIT', _Pid, normal}, State) ->
    {noreply, State};
handle_info({'EXIT', _Pid, Reason}, State) ->
    logger:warning("erlkoenig_elf_srv: linked process died: ~p", [Reason]),
    %% Restart accept loop
    self() ! accept,
    {noreply, State};
handle_info(_Msg, State) ->
    {noreply, State}.

terminate(_Reason, #state{socket_path = Path, listen_sock = LSock}) ->
    catch gen_tcp:close(LSock),
    _ = file:delete(Path),
    ok.

%% ---------------------------------------------------------------------------
%% Accept loop (runs in linked process)
%% ---------------------------------------------------------------------------

accept_loop(Parent, LSock) ->
    case gen_tcp:accept(LSock) of
        {ok, Sock} ->
            Parent ! {client, Sock},
            accept_loop(Parent, LSock);
        {error, closed} ->
            ok;
        {error, Reason} ->
            logger:warning("accept failed: ~p", [Reason]),
            timer:sleep(100),
            accept_loop(Parent, LSock)
    end.

%% ---------------------------------------------------------------------------
%% Client handler (runs in spawned process)
%% ---------------------------------------------------------------------------

handle_client(Sock) ->
    case gen_tcp:recv(Sock, 0, 30000) of
        {ok, Data} ->
            Request = binary_to_term(Data, [safe]),
            Response = handle_request(Request),
            Reply = term_to_binary(Response),
            _ = gen_tcp:send(Sock, Reply),
            %% Support pipelining: try to read another request
            handle_client(Sock);
        {error, closed} ->
            ok;
        {error, timeout} ->
            gen_tcp:close(Sock);
        {error, _Reason} ->
            gen_tcp:close(Sock)
    end.

%% ---------------------------------------------------------------------------
%% Request dispatch
%% ---------------------------------------------------------------------------

handle_request(ping) ->
    pong;
handle_request(version) ->
    {ok, Vsn} = application:get_key(erlkoenig_elf, vsn),
    {version, list_to_binary(Vsn)};
handle_request({analyze, Path}) ->
    with_elf(Path, fun(Elf) -> erlkoenig_elf:analyze(Elf) end);
handle_request({syscalls, Path}) ->
    with_elf(Path, fun(Elf) -> erlkoenig_elf:syscalls(Elf) end);
handle_request({seccomp, Path, json}) ->
    with_elf(Path, fun(Elf) -> erlkoenig_elf:seccomp_json(Elf) end);
handle_request({seccomp, Path, bpf}) ->
    with_elf(Path, fun(Elf) -> erlkoenig_elf:seccomp_bpf(Elf) end);
handle_request({seccomp, Path}) ->
    handle_request({seccomp, Path, json});
handle_request({language, Path}) ->
    with_elf(Path, fun(Elf) -> {ok, erlkoenig_elf:language(Elf)} end);
handle_request({deps, Path}) ->
    with_elf(Path, fun(Elf) -> erlkoenig_elf:deps(Elf) end);
handle_request({patch, Path, Func, Strategy}) ->
    safe_call(fun() -> erlkoenig_elf:patch(Path, Func, Strategy) end);
handle_request(_Unknown) ->
    {error, unknown_request}.

%% ---------------------------------------------------------------------------
%% Helpers
%% ---------------------------------------------------------------------------

with_elf(Path, Fun) ->
    safe_call(fun() ->
        maybe
            ok ?= validate_path(Path),
            {ok, Elf} ?= erlkoenig_elf:parse(Path),
            Fun(Elf)
        end
    end).

safe_call(Fun) ->
    try Fun() of
        {ok, _} = Ok -> Ok;
        {error, _} = Err -> Err
    catch
        error:Reason:Stack ->
            logger:warning("request failed: ~p~n~p", [Reason, Stack]),
            {error, {internal, Reason}};
        throw:Reason ->
            {error, Reason}
    end.

%% Validate that Path is a regular file (no symlink tricks, no directories).
validate_path(Path) when is_binary(Path) ->
    validate_path(binary_to_list(Path));
validate_path(Path) when is_list(Path) ->
    case file:read_link_info(Path) of
        {ok, Info} ->
            case element(3, Info) of
                regular -> ok;
                _ -> {error, {not_regular_file, list_to_binary(Path)}}
            end;
        {error, enoent} ->
            {error, {file_not_found, list_to_binary(Path)}};
        {error, eacces} ->
            {error, {permission_denied, list_to_binary(Path)}};
        {error, Reason} ->
            {error, {Reason, list_to_binary(Path)}}
    end.
