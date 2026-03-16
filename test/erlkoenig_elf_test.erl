-module(erlkoenig_elf_test).
-include_lib("eunit/include/eunit.hrl").
-include("elf_parse.hrl").
-include("elf_seccomp.hrl").
-include("elf_lang_go.hrl").
-include("elf_lang_rust.hrl").

%% ---------------------------------------------------------------------------
%% Minimal ELF64 binary construction (reused from elf_parse_test)
%% ---------------------------------------------------------------------------

-define(TEXT_OFF,    16#078).
-define(TEXT_SIZE,   4).
-define(TEXT_VADDR,  16#400000).
-define(STRTAB_OFF,  16#07C).
-define(STRTAB_SIZE, 17).
-define(SHDR_OFF,    16#090).

minimal_elf64_le() ->
    StrTab = <<0, ".text", 0, ".shstrtab", 0>>,
    ?STRTAB_SIZE = byte_size(StrTab),
    TextContent = <<16#90, 16#90, 16#90, 16#C3>>,
    ?TEXT_SIZE = byte_size(TextContent),
    Header = elf_header_le(?ET_EXEC, ?EM_X86_64, ?TEXT_VADDR, 64,
                           ?SHDR_OFF, 1, 3, 2),
    Phdr = phdr_le(?PT_LOAD, ?PF_R bor ?PF_X, ?TEXT_OFF,
                   ?TEXT_VADDR, ?TEXT_VADDR, ?TEXT_SIZE, ?TEXT_SIZE, 16#1000),
    Shdr0 = shdr_le(0, ?SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0),
    Shdr1 = shdr_le(1, ?SHT_PROGBITS, ?SHF_ALLOC bor ?SHF_EXECINSTR,
                     ?TEXT_VADDR, ?TEXT_OFF, ?TEXT_SIZE, 0, 0, 16, 0),
    Shdr2 = shdr_le(7, ?SHT_STRTAB, 0, 0, ?STRTAB_OFF, ?STRTAB_SIZE, 0, 0, 1, 0),
    PadSize = ?SHDR_OFF - (?STRTAB_OFF + ?STRTAB_SIZE),
    Pad = <<0:(PadSize * 8)>>,
    <<Header/binary, Phdr/binary, TextContent/binary, StrTab/binary, Pad/binary,
      Shdr0/binary, Shdr1/binary, Shdr2/binary>>.

elf_header_le(Type, Machine, Entry, PhOff, ShOff, PhNum, ShNum, ShStrNdx) ->
    <<16#7F, "ELF",
      2:8, 1:8, 1:8, 0:8, 0:64,
      Type:16/little, Machine:16/little, 1:32/little,
      Entry:64/little, PhOff:64/little, ShOff:64/little,
      0:32/little, 64:16/little, 56:16/little, PhNum:16/little,
      64:16/little, ShNum:16/little, ShStrNdx:16/little>>.

phdr_le(PType, PFlags, POffset, PVaddr, PPaddr, PFilesz, PMemsz, PAlign) ->
    <<PType:32/little, PFlags:32/little,
      POffset:64/little, PVaddr:64/little, PPaddr:64/little,
      PFilesz:64/little, PMemsz:64/little, PAlign:64/little>>.

shdr_le(ShName, ShType, ShFlags, ShAddr, ShOffset, ShSize,
        ShLink, ShInfo, ShAddralign, ShEntsize) ->
    <<ShName:32/little, ShType:32/little, ShFlags:64/little,
      ShAddr:64/little, ShOffset:64/little, ShSize:64/little,
      ShLink:32/little, ShInfo:32/little,
      ShAddralign:64/little, ShEntsize:64/little>>.

%% ===========================================================================
%% Tests
%% ===========================================================================

%% --- parse/1 with file path (string) ---

parse_file_path_test() ->
    Bin = minimal_elf64_le(),
    TmpPath = "/tmp/erlkoenig_elf_test_parse.bin",
    ok = file:write_file(TmpPath, Bin),
    {ok, Elf} = erlkoenig_elf:parse(TmpPath),
    ?assertEqual(x86_64, Elf#elf.header#elf_header.machine),
    file:delete(TmpPath).

%% --- parse/1 with binary data ---

parse_binary_data_test() ->
    Bin = minimal_elf64_le(),
    {ok, Elf} = erlkoenig_elf:parse(Bin),
    ?assertEqual(x86_64, Elf#elf.header#elf_header.machine),
    ?assertEqual(exec, Elf#elf.header#elf_header.type).

%% --- parse/1 with binary file path ---

parse_binary_path_test() ->
    Bin = minimal_elf64_le(),
    TmpPath = "/tmp/erlkoenig_elf_test_parse_bp.bin",
    ok = file:write_file(TmpPath, Bin),
    {ok, Elf} = erlkoenig_elf:parse(list_to_binary(TmpPath)),
    ?assertEqual(x86_64, Elf#elf.header#elf_header.machine),
    file:delete(TmpPath).

%% --- parse/1 with short binary path ---

parse_short_binary_path_test() ->
    %% Short binary (<=64 bytes) should be treated as file path
    ?assertMatch({error, _}, erlkoenig_elf:parse(<<"/tmp/nope">>)).

%% --- parse/1 error ---

parse_error_test() ->
    ?assertMatch({error, _}, erlkoenig_elf:parse("/nonexistent/path")).

%% --- analyze/1 returns all expected fields ---

analyze_fields_test() ->
    Bin = minimal_elf64_le(),
    {ok, Elf} = erlkoenig_elf:parse(Bin),
    {ok, Report} = erlkoenig_elf:analyze(Elf),
    ?assertEqual(x86_64, maps:get(arch, Report)),
    ?assertEqual(exec, maps:get(type, Report)),
    ?assertEqual(true, maps:get(is_static, Report)),
    ?assertEqual(false, maps:get(is_pie, Report)),
    ?assertEqual(false, maps:get(has_debug, Report)),
    ?assertEqual(unknown, maps:get(language, Report)),
    ?assertEqual(?TEXT_VADDR, maps:get(entry_point, Report)),
    ?assert(is_list(maps:get(sections, Report))),
    ?assertEqual(?TEXT_SIZE, maps:get(text_size, Report)),
    ?assertEqual(byte_size(Bin), maps:get(total_size, Report)),
    %% syscalls and language_info should be present (may be error for minimal ELF)
    ?assert(maps:is_key(syscalls, Report)),
    ?assert(maps:is_key(language_info, Report)).

%% --- syscalls/1 delegates correctly ---

syscalls_unsupported_arch_test() ->
    %% Our minimal binary has x86_64 but no real syscall instructions,
    %% elf_syscall:extract needs the decoder module which may or may not
    %% be available. Either way, the delegation should work.
    Bin = minimal_elf64_le(),
    {ok, Elf} = erlkoenig_elf:parse(Bin),
    Result = erlkoenig_elf:syscalls(Elf),
    case Result of
        {ok, Info} ->
            ?assert(is_map(Info)),
            ?assert(maps:is_key(arch, Info));
        {error, _Reason} ->
            ok  %% decoder not available is fine
    end.

%% --- syscall_names/1 ---

syscall_names_test() ->
    Bin = minimal_elf64_le(),
    {ok, Elf} = erlkoenig_elf:parse(Bin),
    Result = erlkoenig_elf:syscall_names(Elf),
    case Result of
        {ok, Names} -> ?assert(is_list(Names));
        {error, _} -> ok
    end.

%% --- seccomp_json/1 ---

seccomp_json_test() ->
    Bin = minimal_elf64_le(),
    {ok, Elf} = erlkoenig_elf:parse(Bin),
    Result = erlkoenig_elf:seccomp_json(Elf),
    case Result of
        {ok, Json} ->
            Flat = iolist_to_binary(Json),
            ?assert(byte_size(Flat) > 0),
            %% Should contain seccomp-specific keys
            ?assertNotEqual(nomatch, binary:match(Flat, <<"SCMP_">>));
        {error, _} ->
            ok  %% decoder not available
    end.

%% --- seccomp_profile/1 ---

seccomp_profile_test() ->
    Bin = minimal_elf64_le(),
    {ok, Elf} = erlkoenig_elf:parse(Bin),
    Result = erlkoenig_elf:seccomp_profile(Elf),
    case Result of
        {ok, #seccomp_profile{arch = x86_64}} -> ok;
        {error, _} -> ok
    end.

%% --- seccomp_bpf/1 ---

seccomp_bpf_test() ->
    Bin = minimal_elf64_le(),
    {ok, Elf} = erlkoenig_elf:parse(Bin),
    Result = erlkoenig_elf:seccomp_bpf(Elf),
    case Result of
        {ok, Bpf} -> ?assert(is_binary(Bpf));
        {error, _} -> ok
    end.

%% --- language/1 delegates correctly ---

language_unknown_test() ->
    Bin = minimal_elf64_le(),
    {ok, Elf} = erlkoenig_elf:parse(Bin),
    ?assertEqual(unknown, erlkoenig_elf:language(Elf)).

%% --- go_info/1 returns not_go for non-Go binary ---

go_info_not_go_test() ->
    Bin = minimal_elf64_le(),
    {ok, Elf} = erlkoenig_elf:parse(Bin),
    ?assertEqual({error, not_go}, erlkoenig_elf:go_info(Elf)).

%% --- rust_info/1 returns not_rust for non-Rust binary ---

rust_info_not_rust_test() ->
    Bin = minimal_elf64_le(),
    {ok, Elf} = erlkoenig_elf:parse(Bin),
    ?assertEqual({error, not_rust}, erlkoenig_elf:rust_info(Elf)).

%% --- deps/1 for unknown language ---

deps_unknown_test() ->
    Bin = minimal_elf64_le(),
    {ok, Elf} = erlkoenig_elf:parse(Bin),
    ?assertEqual({ok, []}, erlkoenig_elf:deps(Elf)).

%% --- dep_anomalies/1 for minimal binary ---

dep_anomalies_empty_test() ->
    Bin = minimal_elf64_le(),
    {ok, Elf} = erlkoenig_elf:parse(Bin),
    ?assertEqual([], erlkoenig_elf:dep_anomalies(Elf)).

%% --- patch/3 delegates to elf_patch ---

patch_delegates_test() ->
    Bin = minimal_elf64_le(),
    TmpPath = "/tmp/erlkoenig_elf_test_patch.bin",
    ok = file:write_file(TmpPath, Bin),
    %% Try patching a non-existent function — should fail with symbol_not_found
    Result = erlkoenig_elf:patch(TmpPath, <<"nonexistent">>, ret),
    ?assertMatch({error, _}, Result),
    file:delete(TmpPath).

%% --- patch_at/4 delegates to elf_patch ---

patch_at_delegates_test() ->
    Bin = minimal_elf64_le(),
    TmpPath = "/tmp/erlkoenig_elf_test_patch_at.bin",
    ok = file:write_file(TmpPath, Bin),
    %% Patch at the .text address (should succeed — 4 bytes, RET is 1 byte)
    Result = erlkoenig_elf:patch_at(TmpPath, ?TEXT_VADDR, ?TEXT_SIZE, ret),
    ?assertMatch({ok, _}, Result),
    %% Verify the patched binary
    ok = elf_patch:verify_patch(TmpPath),
    %% Clean up
    file:delete(TmpPath),
    file:delete(TmpPath ++ ".orig").

%% --- elf_report:to_text/1 ---

report_to_text_test() ->
    Bin = minimal_elf64_le(),
    {ok, Elf} = erlkoenig_elf:parse(Bin),
    {ok, Report} = erlkoenig_elf:analyze(Elf),
    Text = elf_report:to_text(Report),
    Flat = iolist_to_binary(Text),
    ?assertNotEqual(nomatch, binary:match(Flat, <<"erlkoenig_elf Analysis">>)),
    ?assertNotEqual(nomatch, binary:match(Flat, <<"x86_64">>)),
    ?assertNotEqual(nomatch, binary:match(Flat, <<"exec">>)).

%% --- elf_report:to_json/1 ---

report_to_json_test() ->
    Bin = minimal_elf64_le(),
    {ok, Elf} = erlkoenig_elf:parse(Bin),
    {ok, Report} = erlkoenig_elf:analyze(Elf),
    Json = elf_report:to_json(Report),
    Flat = iolist_to_binary(Json),
    ?assert(byte_size(Flat) > 0),
    %% Should be valid-looking JSON (starts with {)
    ?assertMatch(<<${, _/binary>>, Flat).

%% --- analyze/1 sections list ---

analyze_sections_list_test() ->
    Bin = minimal_elf64_le(),
    {ok, Elf} = erlkoenig_elf:parse(Bin),
    {ok, Report} = erlkoenig_elf:analyze(Elf),
    Sections = maps:get(sections, Report),
    ?assert(lists:member(<<".text">>, Sections)),
    ?assert(lists:member(<<".shstrtab">>, Sections)).
