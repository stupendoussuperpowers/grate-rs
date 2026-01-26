use core::ffi::{c_char, c_int};
use libc::{EXIT_FAILURE, perror, pid_t};
use std::collections::HashMap;
use std::ffi::CString;
use std::{env, ptr};

const ELINDAPIABORTED: u64 = 0xE001_0001;

/// The signature of a syscall handler function
pub type SyscallHandler = extern "C" fn(
    cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    arg2cage: u64,
    arg3: u64,
    arg3cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32;

unsafe extern "C" {
    // Since we wrap these functions, we need them to have a different name in the rust context.
    // Using link_name to ensure they are mapped to correct sysroot entities.
    #[link_name = "register_handler"]
    fn register_handler_impl(
        cageid: u64,
        syscall_nr: u64,
        handle_flag: u64,
        grateid: u64,
        fn_ptr_addr: u64,
    ) -> c_int;

    #[link_name = "copy_data_between_cages"]
    fn cp_data_impl(
        thiscage: u64,
        targetcage: u64,
        srcaddr: u64,
        srccage: u64,
        destaddr: u64,
        destcage: u64,
        len: u64,
        copytype: u64,
    ) -> c_int;

    #[link_name = "getpid"]
    fn getpid_impl() -> pid_t;

    fn fork() -> pid_t;
    fn execv(prog: *const c_char, argv: *const *mut c_char) -> c_int;
    fn waitpid(pid: pid_t, status: *mut c_int, options: c_int) -> pid_t;
}

// Wrap register_handler, copy_data_between_cages, and getpid to be more Rust-native.
//
// This allows us to use these functions without needing a myriad of unsafe blocks.
//
// Also sticks to the familiar syntax of Result<V, E> return types for these.
pub fn register_handler(
    cageid: u64,
    syscall_nr: u64,
    register_flag: u64,
    grateid: u64,
    handler: SyscallHandler,
) -> Result<(), i32> {
    let fn_ptr_addr = handler as *const () as usize as u64;

    let ret = unsafe {
        register_handler_impl(
            cageid,
            syscall_nr,
            register_flag,
            grateid as u64,
            fn_ptr_addr,
        )
    };

    if ret != 0 {
        return Err(ret as i32);
    }

    Ok(())
}

pub fn copy_data_between_cages(
    thiscage: u64,
    targetcage: u64,
    srcaddr: u64,
    srccage: u64,
    destaddr: u64,
    destcage: u64,
    len: u64,
    copytype: u64,
) -> Result<(), i32> {
    let ret = unsafe {
        cp_data_impl(
            thiscage, targetcage, srcaddr, srccage, destaddr, destcage, len, copytype,
        )
    };

    if ret == ELINDAPIABORTED as i32 {
        return Err(-1);
    }

    Ok(())
}

pub fn getpid() -> i32 {
    unsafe { getpid_impl() }
}

// This function is required by threei to dispatch registered syscalls to this grate.
// We need no_mangle and extern "C" to ensure it's named correctly.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pass_fptr_to_wt(
    fn_ptr_uint: u64,
    cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    arg2cage: u64,
    arg3: u64,
    arg3cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> c_int {
    if fn_ptr_uint == 0 {
        println!("[grate] invalid function pointer");
        return -1;
    }

    unsafe {
        let fn_ptr: extern "C" fn(
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
        ) -> i32 = core::mem::transmute(fn_ptr_uint as usize);

        fn_ptr(
            cageid, arg1, arg1cage, arg2, arg2cage, arg3, arg3cage, arg4, arg4cage, arg5, arg5cage,
            arg6, arg6cage,
        )
    }
}

/// Callback type for cage init execution
pub type CageInitCallback = Box<dyn FnOnce()>;

/// A builder for creating grates with customizable lifecycle hooks
pub struct GrateBuilder {
    handlers: HashMap<u64, SyscallHandler>,
    cage_init: Option<CageInitCallback>,
}

impl GrateBuilder {
    /// Create a new grate builder
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
            cage_init: None,
        }
    }

    /// Register a syscall handler
    pub fn register(mut self, syscall_nr: u64, handler: SyscallHandler) -> Self {
        self.handlers.insert(syscall_nr, handler);
        self
    }

    /// Set a callback to run before exec (in child process, after handler registration)
    pub fn cage_init<F>(mut self, callback: F) -> Self
    where
        F: FnOnce() + 'static,
    {
        self.cage_init = Some(Box::new(callback));
        self
    }

    // Build and run the grate.
    //
    // This is the equivalent of the fork-exec we perform in the main function of C grates.
    pub fn run(self) {
        let argv: Vec<String> = env::args().collect();
        if argv.len() < 2 {
            eprintln!("Usage: {} <program> [args...]", argv[0]);
            std::process::exit(1);
        }

        unsafe {
            let grateid: pid_t = getpid();

            let pid: pid_t = fork();
            if pid < 0 {
                perror(b"fork failed\0".as_ptr() as *const _);
                libc::_exit(EXIT_FAILURE);
            } else if pid == 0 {
                let cageid = getpid() as u64;

                // Register all handlers
                for (syscall_nr, handler) in &self.handlers {
                    match register_handler(cageid, *syscall_nr, 1, grateid as u64, *handler) {
                        Ok(_) => {}
                        Err(_ret) => libc::_exit(EXIT_FAILURE),
                    };
                }

                // Run pre-exec callback if provided
                if let Some(callback) = self.cage_init {
                    callback();
                }

                // Prepare arguments for execv
                let mut cstrings: Vec<CString> = argv[1..]
                    .iter()
                    .map(|s| CString::new(s.as_str()).unwrap())
                    .collect();

                let mut c_argv: Vec<*mut i8> =
                    cstrings.iter_mut().map(|s| s.as_ptr() as *mut i8).collect();

                c_argv.push(ptr::null_mut());

                let path = CString::new(argv[1].as_str()).unwrap();
                execv(path.as_ptr(), c_argv.as_ptr());

                perror(b"execv failed\0".as_ptr() as *const _);
                libc::_exit(EXIT_FAILURE);
            } else {
                waitpid(pid, ptr::null_mut(), 0);
                return;
                // libc::_exit(0);
            }
        }
    }
}
