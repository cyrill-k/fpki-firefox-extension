# Build
- use tinygo for easy export: https://tinygo.org/docs/guides/webassembly/
- `tinygo build -o ../background/main-tiny.wasm -target wasm ./main.go`

# Debug
- Analyze .wasm files: https://github.com/WebAssembly/wabt
- `~/github/wabt/build/wasm-objdump -x -j Import main-tiny.wasm`
- `~/github/wabt/build/wasm-objdump -x -j Export main-tiny.wasm`
