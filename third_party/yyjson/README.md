# yyjson (vendored)

Upstream: https://github.com/ibireme/yyjson, tag `0.13.0`, MIT License.
Files taken unmodified from that tag: `src/yyjson.c`, `src/yyjson.h`, `LICENSE`.
Compile options are set as source properties in the top-level `CMakeLists.txt`:
`YYJSON_DISABLE_FILE`, `YYJSON_DISABLE_UTILS`, `YYJSON_DISABLE_INCR_READER`,
`YYJSON_READER_DEPTH_LIMIT=32`; `yyjson_api` is redefined to empty so the symbols stay hidden.
To update: replace the three files with the ones from the same tag, then update the version pin in `src/json_util.h`.
