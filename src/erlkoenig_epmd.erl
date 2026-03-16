%% @doc Custom EPMD replacement — fixed port, no epmd process.
%%
%% Used via: -start_epmd false -epmd_module erlkoenig_epmd
%% Allows remsh without running the epmd daemon.
-module(erlkoenig_epmd).

-export([start_link/0,
         register_node/2, register_node/3,
         port_please/2, address_please/3,
         names/1]).

start_link() ->
    ignore.

register_node(_Name, _Port) ->
    {ok, 0}.

register_node(_Name, _Port, _Family) ->
    {ok, 0}.

port_please(_Name, _Host) ->
    {port, dist_port(), 5}.

address_please(_Name, Host, _AddressFamily) ->
    case inet:parse_address(Host) of
        {ok, IP} -> {ok, IP};
        _        -> {ok, Host}
    end.

names(_Host) ->
    {ok, []}.

-spec dist_port() -> inet:port_number().
dist_port() ->
    application:get_env(erlkoenig_elf, dist_port, 9103).
