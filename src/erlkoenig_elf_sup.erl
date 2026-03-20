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

-module(erlkoenig_elf_sup).
-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    SocketPath = application:get_env(
        erlkoenig_elf,
        socket_path,
        "/run/erlkoenig_elf/ctl.sock"
    ),
    Children = [
        #{
            id => erlkoenig_elf_srv,
            start => {erlkoenig_elf_srv, start_link, [SocketPath]},
            restart => permanent,
            type => worker
        }
    ],
    {ok, {#{strategy => one_for_one, intensity => 5, period => 10}, Children}}.
