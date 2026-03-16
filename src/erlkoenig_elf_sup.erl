-module(erlkoenig_elf_sup).
-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    SocketPath = application:get_env(erlkoenig_elf, socket_path,
                                     "/run/erlkoenig_elf/ctl.sock"),
    Children = [
        #{id => erlkoenig_elf_srv,
          start => {erlkoenig_elf_srv, start_link, [SocketPath]},
          restart => permanent,
          type => worker}
    ],
    {ok, {#{strategy => one_for_one, intensity => 5, period => 10}, Children}}.
