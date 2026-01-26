## grate-rs

See this example [examples/read_syscall.rs](examples/read_syscall.rs) for a complete usage of this library.

### Example builder pattern

```rust 
fn main() {
    println!("[grate_init] Run any init stuff here, such as imfs_init() or preloads()");
    let builder = GrateBuilder::new()
        .register(0, read_syscall)
        .cage_init(|| println!("[cage_init] Code to run post-fork but pre-exec"));

    // Does the fork and exec(argv[1], &argv[1]);
    builder.run();

    println!(
        "[grate_teardown] Code that runs after the child exits. Run dump_file() or similar things"
    );
}
```

### Wrappers

Grate-rs also provides the following helpers to avoid needless `unsafe` usage for common patterns:

- ```rust
pub fn register_handler(
    cageid: u64,
    syscall_nr: u64,
    register_flag: u64,
    grateid: u64,
    handler: SyscallHandler,
) -> Result<(), i32> 
```

- ```rust
pub fn copy_data_between_cages(
    thiscage: u64,
    targetcage: u64,
    srcaddr: u64,
    srccage: u64,
    destaddr: u64,
    destcage: u64,
    len: u64,
    copytype: u64,
) -> Result<(), i32>
```

- ```rust
pub fn getpid() -> i32
```
