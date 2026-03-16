%% Rust binary analysis records

-ifndef(ELF_LANG_RUST_HRL).
-define(ELF_LANG_RUST_HRL, true).

-record(rust_crate, {
    name    :: binary(),
    version :: binary() | unknown,
    source  :: symtab | panic_strings | comment
}).

-record(rust_info, {
    crates   :: [#rust_crate{}],
    compiler :: binary() | unknown
}).

-endif.
