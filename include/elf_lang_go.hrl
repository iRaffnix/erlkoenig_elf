%% Go binary analysis records
%% Reference: src/debug/buildinfo, src/internal/goarch in Go source

-ifndef(ELF_LANG_GO_HRL).
-define(ELF_LANG_GO_HRL, true).

-record(go_func, {
    name     :: binary(),           %% e.g. <<"github.com/user/pkg.Function">>
    entry    :: non_neg_integer(),  %% absolute address
    package  :: binary()            %% e.g. <<"github.com/user/pkg">>
}).

-record(go_dep, {
    path    :: binary(),     %% e.g. <<"github.com/lib/pq">>
    version :: binary(),     %% e.g. <<"v1.10.9">>
    hash    :: binary()      %% e.g. <<"h1:abc...">>
}).

-record(go_info, {
    version         :: binary(),                    %% e.g. <<"go1.22.1">>
    main_module     :: binary() | undefined,
    mod_version     :: binary() | undefined,
    deps            :: [#go_dep{}],
    functions       :: [#go_func{}],
    build_settings  :: [{binary(), binary()}],       %% key-value from build lines
    go_version_raw  :: binary()
}).

-endif.
