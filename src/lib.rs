use core::ffi::{c_char, c_int};
use libc::{close, pid_t, read, write};
use std::ffi::{CString, c_void};
use std::{env, ptr};

const ELINDAPIABORTED: u64 = 0xE001_0001;

macro_rules! call_sys {
    ($fn:ident ( $($arg:expr),* $(,)? )) => {{
        let ret = $fn($($arg),*);

        if ret < 0 {
            Err(GrateError::CoordinationError(
                concat!(stringify!($fn),
                " failed:",
                stringify!(ret))
            ))
        } else {
            Ok(ret)
        }
    }}
}

// Error types that can occur during grate execution
#[derive(Debug)]
pub enum GrateError {
    CoordinationError(&'static str),
    HandlerRegistrationError(i32),
    CopyDataError(i32),
}

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
    fn pipe(fds: *mut c_int) -> c_int;
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
) -> Result<(), GrateError> {
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

    match ret {
        0 => Err(GrateError::HandlerRegistrationError(ret)),
        _ => Ok(()),
    }
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
) -> Result<(), GrateError> {
    let ret = unsafe {
        cp_data_impl(
            thiscage, targetcage, srcaddr, srccage, destaddr, destcage, len, copytype,
        )
    };

    match ret as u64 {
        ELINDAPIABORTED => Err(GrateError::CopyDataError(ELINDAPIABORTED as i32)),
        _ => Ok(()),
    }
}

pub fn getcageid() -> u64 {
    unsafe { getpid_impl() as u64 }
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
    handlers: Vec<(u64, SyscallHandler)>,
    cage_init: Option<CageInitCallback>,
    cage_status: i32,
}

impl GrateBuilder {
    /// Create a new grate builder
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
            cage_init: None,
            cage_status: -1,
        }
    }

    /// Register a syscall handler
    pub fn register(mut self, syscall_nr: u64, handler: SyscallHandler) -> Self {
        self.handlers.push((syscall_nr, handler));
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
    pub fn run(mut self) -> Result<i32, GrateError> {
        let argv: Vec<String> = env::args().collect();
        if argv.len() < 2 {
            eprintln!("Usage: {} <program> [args...]", argv[0]);
            std::process::exit(1);
        }

        unsafe {
            let grateid = getcageid();

            let mut fds = [0; 2];
            let _ = call_sys!(pipe(fds.as_mut_ptr()))?;

            let read_fd = fds[0];
            let write_fd = fds[1];

            match call_sys!(fork())? {
                0 => {
                    let _ = call_sys!(close(write_fd))?;

                    let mut buf: u8 = 0;
                    let _ = call_sys!(read(read_fd, &mut buf as *mut u8 as *mut c_void, 1))?;

                    let _ = call_sys!(close(read_fd))?;

                    // Register all handlers
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

                    let _ = call_sys!(execv(path.as_ptr(), c_argv.as_ptr()))?;
                }
                cageid => {
                    let _ = call_sys!(close(read_fd));
                    for (syscall_nr, handler) in &self.handlers {
                        match register_handler(
                            cageid as u64,
                            *syscall_nr,
                            1,
                            grateid as u64,
                            *handler,
                        ) {
                            Ok(_) => {}
                            Err(ret) => return Err(ret),
                        };
                    }

                    let signal: u8 = 1;
                    let _ = call_sys!(write(write_fd, &signal as *const u8 as *const c_void, 1))?;

                    let _ = call_sys!(close(write_fd))?;

                    let mut status: i32 = 0;
                    let _ = call_sys!(waitpid(cageid, &mut status as *mut i32 as *mut c_int, 0))?;

                    self.cage_status = status;
                }
            }
        }

        Ok(self.cage_status)
    }
}
