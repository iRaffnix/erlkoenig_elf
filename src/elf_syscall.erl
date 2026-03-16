%%% @doc High-level syscall extraction from parsed ELF binaries.
%%%
%%% Combines the ELF parser, architecture-specific decoders, and the
%%% syscall database to produce a complete syscall profile for a binary.
-module(elf_syscall).

-include("elf_parse.hrl").

-export([extract/1, numbers/1, names/1, categories/1]).

%% ---------------------------------------------------------------------------
%% API
%% ---------------------------------------------------------------------------

-spec extract(#elf{}) ->
    {ok, #{
        arch => x86_64 | aarch64,
        resolved => #{non_neg_integer() => binary()},
        unresolved_count => non_neg_integer(),
        sites => [#{addr => non_neg_integer(), syscall_nr => non_neg_integer() | unresolved}],
        categories => #{atom() => [binary()]}
    }} | {error, term()}.
extract(#elf{header = #elf_header{machine = Arch}} = Elf)
  when Arch =:= x86_64; Arch =:= aarch64 ->
    case decoder_module(Arch) of
        {error, _} = Err -> Err;
        {ok, Mod} ->
            ExecShdrs = elf_parse:executable_sections(Elf),
            {AllNrs, TotalUnresolved, AllSites} =
                lists:foldl(
                    fun(Shdr, {NrsAcc, UnresAcc, SitesAcc}) ->
                        case elf_parse:section_data(Shdr, Elf) of
                            {ok, Data} ->
                                {Nrs, Unres} = Mod:extract_syscalls(Data),
                                Sites = build_sites(Mod, Data, Shdr),
                                {ordsets:union(NrsAcc, ordsets:from_list(Nrs)),
                                 UnresAcc + Unres,
                                 SitesAcc ++ Sites};
                            _ ->
                                {NrsAcc, UnresAcc, SitesAcc}
                        end
                    end,
                    {ordsets:new(), 0, []},
                    ExecShdrs),
            Resolved = lists:foldl(
                fun(Nr, Acc) ->
                    case elf_syscall_db:name(Arch, Nr) of
                        {ok, Name} -> Acc#{Nr => Name};
                        error -> Acc#{Nr => <<"unknown">>}
                    end
                end,
                #{},
                AllNrs),
            Cats = build_categories(maps:values(Resolved)),
            {ok, #{
                arch => Arch,
                resolved => Resolved,
                unresolved_count => TotalUnresolved,
                sites => AllSites,
                categories => Cats
            }}
    end;
extract(#elf{header = #elf_header{machine = _}}) ->
    {error, unsupported_arch}.

-spec numbers(#elf{}) -> {ok, ordsets:ordset(non_neg_integer())} | {error, term()}.
numbers(Elf) ->
    case extract(Elf) of
        {ok, #{resolved := Resolved}} ->
            {ok, ordsets:from_list(maps:keys(Resolved))};
        {error, _} = Err -> Err
    end.

-spec names(#elf{}) -> {ok, ordsets:ordset(binary())} | {error, term()}.
names(Elf) ->
    case extract(Elf) of
        {ok, #{resolved := Resolved}} ->
            {ok, ordsets:from_list(maps:values(Resolved))};
        {error, _} = Err -> Err
    end.

-spec categories(#elf{}) -> {ok, #{atom() => [binary()]}} | {error, term()}.
categories(Elf) ->
    case extract(Elf) of
        {ok, #{categories := Cats}} -> {ok, Cats};
        {error, _} = Err -> Err
    end.

%% ---------------------------------------------------------------------------
%% Internal
%% ---------------------------------------------------------------------------

-spec decoder_module(x86_64 | aarch64) ->
    {ok, elf_decode_x86_64 | elf_decode_aarch64} | {error, unsupported_arch}.
decoder_module(x86_64) ->
    check_module(elf_decode_x86_64);
decoder_module(aarch64) ->
    check_module(elf_decode_aarch64).

-spec check_module(elf_decode_x86_64 | elf_decode_aarch64) ->
    {ok, elf_decode_x86_64 | elf_decode_aarch64} | {error, unsupported_arch}.
check_module(Mod) ->
    case code:ensure_loaded(Mod) of
        {module, Mod} -> {ok, Mod};
        {error, _}    -> {error, unsupported_arch}
    end.

-spec build_sites(module(), binary(), #elf_shdr{}) ->
    [#{addr => non_neg_integer(), syscall_nr => non_neg_integer() | unresolved}].
build_sites(Mod, Data, #elf_shdr{addr = BaseAddr}) ->
    Insns = Mod:decode_all(Data),
    SyscallType = case Mod of
        elf_decode_x86_64  -> syscall;
        elf_decode_aarch64 -> svc
    end,
    SyscallOffsets = [I || I <- Insns, element(4, I) =:= SyscallType],
    lists:map(
        fun(Insn) ->
            Off = element(2, Insn),
            Nr = Mod:resolve_syscall(Data, Off, Insns),
            #{addr => BaseAddr + Off, syscall_nr => Nr}
        end,
        SyscallOffsets).

-spec build_categories([binary()]) -> #{atom() => [binary()]}.
build_categories(Names) ->
    Unique = ordsets:from_list(Names),
    lists:foldl(
        fun(Name, Acc) ->
            Cat = elf_syscall_db:category(Name),
            Existing = maps:get(Cat, Acc, []),
            Acc#{Cat => ordsets:add_element(Name, Existing)}
        end,
        #{},
        Unique).
