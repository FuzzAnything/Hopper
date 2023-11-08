use crate::{config, error, execute::*, feedback::*, runtime::*, TimeUsage};
use eyre::Context;
use forksrv::ForkSrv;
use ntapi;
use std::io::prelude::*;
use winapi;

pub static HOPPER_USE_THREAD: &str = "HOPPER_USE_THREAD";
pub static HOPPER_USE_THREAD_NUM: &str = "HOPPER_USE_THREAD_NUM";
pub const WAIT_PID_TIMEOUT: u32 = 3000;
pub static HOPPER_ENABLE_CPU_BINDING_VAR: &str = "HOPPER_ENABLE_CPU_BINDING_VAR";

extern "system" {
    fn CsrClientConnectToServer(
        ObjectDirectory: winapi::shared::ntdef::PWSTR,
        ServerId: winapi::shared::ntdef::ULONG,
        ConnectionInfo: winapi::shared::ntdef::PVOID,
        ConnectionInfoSize: winapi::shared::ntdef::ULONG,
        ServerToServerCall: winapi::shared::ntdef::PBOOLEAN,
    ) -> winapi::shared::ntdef::NTSTATUS;
}

pub fn check_hopper_use_thread_win() -> bool {
    if let Ok(enable) = std::env::var(crate::config::HOPPER_USE_THREAD) {
        if enable == "1" {
            return true;
        }
        false
    } else {
        false
    }
}

pub fn get_hopper_use_thread_num() -> i32 {
    if let Ok(num) = std::env::var(crate::config::HOPPER_USE_THREAD_NUM) {
        num.parse::<i32>().unwrap()
    } else {
        100
    }
}

impl ForkSrv {
    pub fn thread_loop_win(&mut self) -> eyre::Result<()> {
        let mut executor = super::Executor::new();
        executor.set_timeout(self.timeout_limit);
        let mut exec_usage = TimeUsage::default();
        let start_at = std::time::Instant::now();
        disable_coverage_feedback();
        let raw_data_base = format!("{}_RAW_DATA_BASE\x00", crate::config::TASK_NAME);
        let id =
            crate::execute::hopper_create_file_mapping(0, 0x100000, raw_data_base.as_ptr() as u32)
                .unwrap();
        let ptr = match crate::execute::hopper_map_view_of_file_ex(
            id,
            0,
            0,
            0,
            crate::config::RAW_DATA_PTR as *mut std::os::raw::c_void,
        ) {
            Ok(ptr) => {
                crate::log!(
                    info,
                    "{:?} thread_loop shm  {:?}",
                    ptr,
                    std::io::Error::last_os_error()
                );
                ptr
            }
            Err(_) => {
                crate::log!(
                    error,
                    "thread_loop shm error {:?}",
                    std::io::Error::last_os_error()
                );
                crate::execute::NULL
            }
        };
        crate::log!(info, "start thread loop ! shm {:?}", ptr);
        let event_str = format!("{}_CHILD_FINISH\x00", crate::config::TASK_NAME);
        let event_child_finish = crate::execute::creat_event(event_str);
        let event_str = format!("{}_PARENT_READY\x00", crate::config::TASK_NAME);
        let event_parent_ready = crate::execute::creat_event(event_str);
        let event_str = format!("{}_CHILD_READY\x00", crate::config::TASK_NAME);
        let event_child_ready = crate::execute::creat_event(event_str);
        let event_str = format!("{}_THREAD_READY\x00", crate::config::TASK_NAME);
        let event_thread_ready = crate::execute::creat_event(event_str);
        'outer: loop {
            let before_fork = std::time::Instant::now();
            let mut pi: crate::execute::ProcessInformation = crate::execute::ProcessInformation {
                hProcess: crate::execute::NULL,
                hThread: crate::execute::NULL,
                dwProcessId: 0,
                dwThreadId: 0,
            };
            let pid = crate::execute::fork(&mut pi);
            if pid > 0 {
                crate::log!(info, "pid {}!,handle {:?}", pid, pi.hProcess);
                let wait_res = unsafe {
                    winapi::um::synchapi::WaitForSingleObject(
                        event_child_ready,
                        config::WAIT_PID_TIMEOUT - 1000,
                    )
                };
                unsafe {
                    winapi::um::synchapi::ResetEvent(event_child_ready);
                }
                if wait_res != 0 {
                    crate::log!(warn, "fork error");
                    crate::execute::terminate_close_child(pi);
                    continue;
                }
                close_child(pi);
                crate::log!(
                    debug,
                    "fork ==> duration:{:?}",
                    before_fork.elapsed().as_micros()
                );
                let mut raw_buf = crate::config::RAW_DATA_PTR as *mut crate::execute::RawData;
                let mut child_procrss_thread_cnt = 0;
                loop {
                    if child_procrss_thread_cnt > crate::config::get_hopper_use_thread_num() {
                        unsafe {
                            (*raw_buf).cmd = 0;
                            winapi::um::synchapi::SetEvent(event_parent_ready);
                            winapi::um::synchapi::WaitForSingleObject(
                                event_child_finish,
                                config::WAIT_PID_TIMEOUT + 2000,
                            );
                            winapi::um::synchapi::ResetEvent(event_child_finish);
                        }
                        break;
                    }
                    unsafe {
                        libc::memset(crate::config::RAW_DATA_PTR as *mut libc::c_void, 0, 0x20000);
                        (*raw_buf).event_child_finish = event_child_finish;
                        (*raw_buf).event_thread_ready = event_thread_ready;
                    }
                    let cmd: ForkCmd =
                        io_utils::receive_line(&mut self.reader).context("fail to receive cmd")?;
                    match cmd {
                        ForkCmd::Execute => {
                            child_procrss_thread_cnt += 1;
                            crate::log!(debug, "receive {}-th program..", executor.count());

                            let buf = self.read_buf()?;
                            crate::log!(debug, "program: {}", buf);
                            self.feedback.clear();
                            unsafe {
                                (*raw_buf).program_size = buf.len();
                                for (i, &item) in buf.as_bytes().iter().enumerate() {
                                    (*raw_buf).program[i] = item as u8;
                                }
                                (*raw_buf).cmd = 1;

                                winapi::um::synchapi::SetEvent(event_parent_ready);
                            }
                            unsafe {
                                let wait_res = winapi::um::synchapi::WaitForSingleObject(
                                    event_child_finish,
                                    config::WAIT_PID_TIMEOUT + 2000,
                                );
                                winapi::um::synchapi::ResetEvent(event_child_finish);
                                if wait_res != 0 {
                                    crate::log!(
                                        error,
                                        "child error, break loop, wait_res: {}",
                                        wait_res
                                    );
                                    let status = StatusType::Normal;
                                    writeln!(self.writer, "{}", status.serialize()?)?;
                                    break;
                                }
                            };
                            crate::log!(
                                debug,
                                "wait_res {}, thread_cnt {}",
                                wait_res,
                                child_procrss_thread_cnt
                            );
                            let exit_code = unsafe { (*raw_buf).exit_code };
                            let status = if exit_code == 0 {
                                StatusType::Normal
                            } else if exit_code == 259 {
                                if unsafe { (*raw_buf).not_in_eval } == 0 {
                                    StatusType::Timeout
                                } else {
                                    StatusType::Normal
                                }
                            } else if unsafe { (*raw_buf).not_in_eval } == 0 {
                                StatusType::Crash {
                                    signal: exit_code as u32,
                                }
                            } else {
                                StatusType::Normal
                            };

                            writeln!(self.writer, "{}", status.serialize()?)?;
                            self.writer.flush()?;
                            if exit_code != 0 {
                                crate::log!(
                                    debug,
                                    "exec_break_loop ==> execcode: {}, not in eval: {}",
                                    exit_code,
                                    unsafe { (*raw_buf).not_in_eval }
                                );
                                break;
                            }
                            crate::log!(debug, "exec_normal ==> exitcode: {}", exit_code);
                        }
                        ForkCmd::Review => {
                            crate::log!(
                                debug,
                                "receive {}-th program for review..",
                                executor.count()
                            );
                            let buf = self.read_buf()?;
                            crate::log!(debug, "program: {}", buf);
                            self.feedback.clear();
                            // make timeout longer
                            executor.set_timeout(self.timeout_limit * 3);
                            let status = {
                                let _counter = exec_usage.count();
                                executor.execute(|| {
                                    let mut program = self.read_program(&buf)?;
                                    program.review()
                                })
                            };
                            executor.set_timeout(self.timeout_limit);
                            crate::log!(debug, "review status: {:?}", status);
                            writeln!(self.writer, "{}", status.serialize()?)?;
                            self.writer.flush()?;
                        }
                        ForkCmd::Finish => {
                            crate::log!(warn, "break server loop");
                            let all_secs = start_at.elapsed().as_secs();
                            crate::log!(
                                info,
                                "Time uasge : exec {} - {} ",
                                exec_usage.percent(all_secs),
                                exec_usage.avg_ms()
                            );
                            unsafe {
                                (*raw_buf).cmd = 0;
                                winapi::um::synchapi::SetEvent(event_parent_ready);
                            }
                            break 'outer;
                        }
                        ForkCmd::Sanitize(f) => {
                            crate::log!(
                                debug,
                                "receive {}-th program for sanitize..",
                                executor.count()
                            );
                            let buf = self.read_buf()?;
                            self.feedback.clear();
                            let status = {
                                let _counter = exec_usage.count();
                                executor.execute(|| {
                                    let mut program = self.read_program(&buf)?;
                                    program.sanitize(f);
                                })
                            };
                            let last_stmt = self.feedback.last_stmt_index();
                            // SanitizeChecker::check_illegal_free(f, last_stmt)?;
                            executor.set_timeout(self.timeout_limit);
                            crate::log!(debug, "sanitize status: {:?}", status);
                            writeln!(self.writer, "{}", status.serialize()?)?;
                            self.writer.flush()?;
                        }
                    }
                }
            } else {
                unsafe {
                    winapi::um::synchapi::SetEvent(event_child_ready);
                }
                crate::execute::register_execption_handler_thread();
                crate::execute::register_signal_handler_thread();
                let mut raw_buf = crate::config::RAW_DATA_PTR as *mut crate::execute::RawData;
                loop {
                    unsafe {
                        let _ = winapi::um::synchapi::WaitForSingleObject(
                            event_parent_ready,
                            0xffffffff,
                        );
                        winapi::um::synchapi::ResetEvent(event_parent_ready);
                    }
                    let cmd = unsafe { (*raw_buf).cmd };
                    match cmd {
                        1 => {
                            let (t_handle, _thread_id) = unsafe {
                                (*raw_buf).not_in_eval = 1;
                                crate::execute::create_thread(
                                    Some(thread_exec),
                                    thread_fun as *mut winapi::ctypes::c_void,
                                )
                            };
                            if t_handle == crate::execute::NULL {
                                let mut child_log = std::fs::OpenOptions::new()
                                    .write(true)
                                    .append(true)
                                    .create(true)
                                    .open("child_log.txt")
                                    .unwrap();
                                unsafe {
                                    writeln!(
                                        child_log,
                                        "create thread error: {}",
                                        std::io::Error::last_os_error()
                                    )
                                    .unwrap();
                                    (*raw_buf).not_in_eval = 1;
                                    (*raw_buf).exit_code = 0xcafecafe_u64;
                                    winapi::um::synchapi::SetEvent(event_child_finish);
                                    winapi::um::processthreadsapi::ExitProcess(0);
                                }
                            }

                            unsafe { winapi::um::processthreadsapi::ResumeThread(t_handle) };
                            unsafe {
                                let wait_res = winapi::um::synchapi::WaitForSingleObject(
                                    event_thread_ready,
                                    config::WAIT_PID_TIMEOUT,
                                );
                                winapi::um::synchapi::ResetEvent(event_thread_ready);
                                if wait_res != 0 {
                                    (*raw_buf).not_in_eval = 1;
                                    (*raw_buf).exit_code = 0xcafecafe_u64;
                                    winapi::um::synchapi::SetEvent(event_child_finish);
                                    crate::execute::do_close_handle(t_handle);
                                    winapi::um::processthreadsapi::ExitProcess(0);
                                }
                            }
                            let wait_res = unsafe {
                                winapi::um::synchapi::WaitForSingleObject(
                                    t_handle,
                                    config::WAIT_PID_TIMEOUT,
                                )
                            };
                            crate::execute::do_close_handle(t_handle);
                            if wait_res == 0x102 {
                                unsafe {
                                    (*raw_buf).exit_code = 259;
                                };
                            }

                            let exit_code = unsafe { (*raw_buf).exit_code };
                            if exit_code == 0 {
                                unsafe {
                                    winapi::um::synchapi::SetEvent(event_child_finish);
                                };
                            } else {
                                unsafe {
                                    winapi::um::synchapi::SetEvent(event_child_finish);
                                    winapi::um::processthreadsapi::ExitProcess(0);
                                }
                            }
                        }
                        _ => unsafe {
                            winapi::um::synchapi::SetEvent(event_child_finish);
                            winapi::um::processthreadsapi::ExitProcess(0);
                        },
                    }
                }
            }
            unsafe {
                winapi::um::synchapi::ResetEvent(event_child_finish);
                winapi::um::synchapi::ResetEvent(event_parent_ready);
                winapi::um::synchapi::ResetEvent(event_child_ready);
                winapi::um::synchapi::ResetEvent(event_thread_ready);
            }
        }
        Ok(())
    }
}

pub fn thread_fun() {
    let mut _thread_log = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .open("thread_log.txt")
        .unwrap();

    let mut raw_buf_thread = crate::config::RAW_DATA_PTR as *mut crate::execute::RawData;
    let buf = unsafe {
        String::from_raw_parts(
            (*raw_buf_thread).program.as_mut_ptr(),
            (*raw_buf_thread).program_size,
            (*raw_buf_thread).program_size,
        )
    };
    let buf = buf.replace("\x00", "");
    let mut program = read_program(&buf, true).unwrap();
    unsafe { winapi::um::synchapi::SetEvent((*raw_buf_thread).event_thread_ready) };
    unsafe { (*raw_buf_thread).not_in_eval = 0 }
    let _ = program.eval();
    unsafe {
        (*raw_buf_thread).not_in_eval = 1;
        (*raw_buf_thread).exit_code = 0;
        (*raw_buf_thread).cmd = 0;
        let size = crate::canary::MEM_OFFSET.load(std::sync::atomic::Ordering::SeqCst);
        let _ = region::protect(
            crate::config::CANARY_PTR as *mut std::ffi::c_void,
            size,
            region::Protection::READ_WRITE,
        );
        libc::memset(crate::config::CANARY_PTR as *mut libc::c_void, 0, size);
    }
    crate::canary::MEM_OFFSET.store(0, std::sync::atomic::Ordering::SeqCst);
    unsafe {
        winapi::um::processthreadsapi::ExitThread(0);
    };
}

unsafe extern "system" fn thread_exec(args: winapi::shared::minwindef::LPVOID) -> u32 {
    crate::execute::register_execption_handler_thread();
    crate::execute::register_signal_handler_thread();
    let fun = std::intrinsics::transmute::<winapi::shared::minwindef::LPVOID, fn()>(args);
    fun();
    0
}

const E_HANDLE: u32 = 0x80070006;
unsafe extern "system" fn execption_handler(
    exception_info: winapi::um::winnt::PEXCEPTION_POINTERS,
) -> i32 {
    let rec = &(*(*exception_info).ExceptionRecord);
    let code = rec.ExceptionCode;
    match code {
        //SEGV
        winapi::um::minwinbase::EXCEPTION_ACCESS_VIOLATION |
        winapi::um::minwinbase::EXCEPTION_ARRAY_BOUNDS_EXCEEDED |
        winapi::um::minwinbase::EXCEPTION_STACK_OVERFLOW |
        winapi::um::minwinbase::EXCEPTION_DATATYPE_MISALIGNMENT |
        winapi::um::minwinbase::EXCEPTION_IN_PAGE_ERROR |
        //PPE
        winapi::um::minwinbase::EXCEPTION_FLT_DENORMAL_OPERAND |
        winapi::um::minwinbase::EXCEPTION_FLT_DIVIDE_BY_ZERO |
        winapi::um::minwinbase::EXCEPTION_FLT_INEXACT_RESULT |
        winapi::um::minwinbase::EXCEPTION_FLT_INVALID_OPERATION |
        winapi::um::minwinbase::EXCEPTION_FLT_OVERFLOW |
        winapi::um::minwinbase::EXCEPTION_FLT_STACK_CHECK |
        winapi::um::minwinbase::EXCEPTION_FLT_UNDERFLOW |
        winapi::um::minwinbase::EXCEPTION_INT_DIVIDE_BY_ZERO |
        winapi::um::minwinbase::EXCEPTION_INT_OVERFLOW |
        //ILL
        winapi::um::minwinbase::EXCEPTION_ILLEGAL_INSTRUCTION |
        winapi::um::minwinbase::EXCEPTION_PRIV_INSTRUCTION
        => {
            do_terminate_process(ntapi::ntpsapi::NtCurrentProcess,code as i32);
        },
        E_HANDLE => {
            do_terminate_process(ntapi::ntpsapi::NtCurrentProcess,0);
        }
        _ => return winapi::vc::excpt::EXCEPTION_CONTINUE_SEARCH
    };
    0
}
pub struct RawData {
    pub cmd: i64,
    pub exit_code: u64,
    pub event_child_finish: *mut winapi::ctypes::c_void,
    pub event_thread_ready: *mut winapi::ctypes::c_void,
    pub not_in_eval: u64,
    pub program_size: usize,
    pub program: [u8; 0x10000],
}

unsafe extern "system" fn execption_handler_thread(
    exception_info: winapi::um::winnt::PEXCEPTION_POINTERS,
) -> i32 {
    let rec = &(*(*exception_info).ExceptionRecord);
    let code = rec.ExceptionCode;
    let mut raw_buf_thread = crate::config::RAW_DATA_PTR as *mut RawData;
    (*raw_buf_thread).exit_code = code as u64;
    winapi::um::synchapi::SetEvent((*raw_buf_thread).event_child_finish);
    if code == 541541187_u32 {
        ntapi::ntpsapi::NtTerminateProcess(ntapi::ntpsapi::NtCurrentProcess, code as i32);
    }
    winapi::um::processthreadsapi::ExitProcess(code);
    0
}

extern "system" {
    pub fn signal(sig: i32, handler: Option<unsafe extern "system" fn(i32) -> ()>);
}

const SIGINT: i32 = 2;
const SIGILL: i32 = 4;
const SIGFPE: i32 = 8;
const SIGSEGV: i32 = 11;
const SIGTERM: i32 = 15;
const SIGBREAK: i32 = 21;
const SIGABRT: i32 = 22;
unsafe extern "system" fn signal_handler(sig: i32) {
    do_terminate_process(ntapi::ntpsapi::NtCurrentProcess, sig as i32);
}

unsafe extern "system" fn signal_handler_thread(sig: i32) {
    let mut raw_buf_thread = crate::config::RAW_DATA_PTR as *mut RawData;
    (*raw_buf_thread).exit_code = sig as u64;
    winapi::um::synchapi::SetEvent((*raw_buf_thread).event_child_finish);
    winapi::um::processthreadsapi::ExitProcess(sig as u32);
}

pub fn register_execption_handler() -> winapi::shared::ntdef::HANDLE {
    unsafe { winapi::um::errhandlingapi::AddVectoredExceptionHandler(1, Some(execption_handler)) }
}

pub fn register_execption_handler_thread() -> winapi::shared::ntdef::HANDLE {
    unsafe {
        winapi::um::errhandlingapi::AddVectoredExceptionHandler(1, Some(execption_handler_thread))
    }
}

pub fn register_signal_handler() {
    unsafe { signal(SIGABRT, Some(signal_handler)) };
}

pub fn register_signal_handler_thread() {
    unsafe { signal(SIGINT, Some(signal_handler_thread)) };
    unsafe { signal(SIGILL, Some(signal_handler_thread)) };
    unsafe { signal(SIGFPE, Some(signal_handler_thread)) };
    unsafe { signal(SIGSEGV, Some(signal_handler_thread)) };
    unsafe { signal(SIGTERM, Some(signal_handler_thread)) };
    unsafe { signal(SIGBREAK, Some(signal_handler_thread)) };
    unsafe { signal(SIGABRT, Some(signal_handler_thread)) };
}

pub fn _remove_handler(handler_handle: winapi::shared::ntdef::HANDLE) {
    unsafe { winapi::um::errhandlingapi::RemoveVectoredExceptionHandler(handler_handle) };
}

fn connect_csr_child() -> bool {
    let ntdll_name: winapi::um::winnt::LPCSTR = "ntdll.dll\x00".as_ptr() as *const i8;
    let ntdll: winapi::shared::minwindef::HMODULE =
        unsafe { winapi::um::libloaderapi::GetModuleHandleA(ntdll_name) };
    let kernelbase_name: winapi::um::winnt::LPCSTR = "kernelbase.dll\x00".as_ptr() as *const i8;
    let kernelbase: winapi::shared::minwindef::HMODULE =
        unsafe { winapi::um::libloaderapi::GetModuleHandleA(kernelbase_name) };
    let csr_data_rva_x64 = 0x16ac08;
    let csr_data_size_x64 = 0xf8;
    let p_csr_data = (ntdll as u64 + csr_data_rva_x64 as u64) as *mut winapi::ctypes::c_void;
    unsafe { winapi::um::winnt::RtlZeroMemory(p_csr_data, csr_data_size_x64) };

    let p_ctrl_routine = unsafe {
        winapi::um::libloaderapi::GetProcAddress(
            kernelbase,
            "CtrlRoutine\x00".as_ptr() as *const i8,
        )
    } as *mut winapi::ctypes::c_void;
    let buf: [u64; 1] = [p_ctrl_routine as u64; 1];
    let mut session_id: winapi::shared::minwindef::DWORD = 0;
    unsafe {
        winapi::um::processthreadsapi::ProcessIdToSessionId(
            winapi::um::processthreadsapi::GetProcessId(
                winapi::um::processthreadsapi::GetCurrentProcess(),
            ),
            &mut session_id,
        );
    }
    let sessions_str = format!("\\Sessions\\{}\\Windows\x00\x00\x00\x00", session_id);
    let sessions_bytes = sessions_str.as_bytes();
    let mut sessions_wchar_vec: Vec<winapi::shared::ntdef::WCHAR> = Vec::new();
    for c in sessions_bytes.iter() {
        sessions_wchar_vec.push(*c as winapi::shared::ntdef::WCHAR);
    }
    while sessions_wchar_vec.len() != 100 {
        sessions_wchar_vec.push(0_u16);
    }
    let mut trash: winapi::shared::ntdef::BOOLEAN = 0;
    let res = unsafe {
        CsrClientConnectToServer(
            sessions_wchar_vec.as_ptr() as winapi::shared::ntdef::PWSTR,
            1,
            buf.as_ptr() as winapi::shared::ntdef::PVOID,
            8,
            &mut trash,
        )
    };
    if let false = winapi::shared::ntdef::NT_SUCCESS(res) {
        crate::log!(
            error,
            "CsrClientConnectToServer1 error, errno: {}",
            std::io::Error::last_os_error()
        );
        return false;
    }
    let buf: [char; 0x240] = ['\x00'; 0x240];
    let mut trash: winapi::shared::ntdef::BOOLEAN = 0;
    let res = unsafe {
        CsrClientConnectToServer(
            sessions_wchar_vec.as_ptr() as winapi::shared::ntdef::PWSTR,
            3,
            buf.as_ptr() as winapi::shared::ntdef::PVOID,
            0x240,
            &mut trash,
        )
    };
    if let false = winapi::shared::ntdef::NT_SUCCESS(res) {
        crate::log!(
            error,
            "CsrClientConnectToServer2 error, errno: {}",
            std::io::Error::last_os_error()
        );
        return false;
    }
    let res = unsafe { ntapi::ntrtl::RtlRegisterThreadWithCsrss() };
    if let false = winapi::shared::ntdef::NT_SUCCESS(res) {
        crate::log!(
            error,
            "RtlRegisterThreadWithCsrss error, errno: {}",
            std::io::Error::last_os_error()
        );
        return false;
    }
    true
}

pub fn fork(
    lp_process_information: winapi::um::processthreadsapi::LPPROCESS_INFORMATION,
) -> winapi::shared::minwindef::DWORD {
    let mut process_handle: winapi::shared::ntdef::HANDLE = winapi::shared::ntdef::NULL;
    let mut thread_handle: winapi::shared::ntdef::HANDLE = winapi::shared::ntdef::NULL;
    let process_desired_access: winapi::um::winnt::ACCESS_MASK = winapi::um::winnt::MAXIMUM_ALLOWED;
    let thread_desired_access: winapi::um::winnt::ACCESS_MASK = winapi::um::winnt::MAXIMUM_ALLOWED;
    let process_flags: winapi::shared::ntdef::ULONG =
        ntapi::ntpsapi::PROCESS_CREATE_FLAGS_INHERIT_FROM_PARENT
            | ntapi::ntpsapi::PROCESS_CREATE_FLAGS_INHERIT_HANDLES;
    let thread_flags: winapi::shared::ntdef::ULONG =
        ntapi::ntpsapi::THREAD_CREATE_FLAGS_CREATE_SUSPENDED;
    let u: ntapi::ntpsapi::PS_CREATE_INFO_u = ntapi::ntpsapi::PS_CREATE_INFO_u {
        FileHandle: winapi::shared::ntdef::NULL,
    };
    let mut create_info: ntapi::ntpsapi::PS_CREATE_INFO = ntapi::ntpsapi::PS_CREATE_INFO {
        Size: 0,
        State: 0,
        u,
    };
    create_info.Size = std::mem::size_of::<ntapi::ntpsapi::PS_CREATE_INFO>();
    let results: winapi::shared::ntdef::NTSTATUS = unsafe {
        ntapi::ntpsapi::NtCreateUserProcess(
            &mut process_handle,
            &mut thread_handle,
            process_desired_access,
            thread_desired_access,
            0 as winapi::shared::ntdef::POBJECT_ATTRIBUTES,
            0 as winapi::shared::ntdef::POBJECT_ATTRIBUTES,
            process_flags,
            thread_flags,
            0 as winapi::shared::ntdef::PVOID,
            &mut create_info,
            0 as ntapi::ntpsapi::PPS_ATTRIBUTE_LIST,
        )
    };
    if results == 0 {
        //notify_csrss_parent(process_handle,thread_handle);
        unsafe {
            (*lp_process_information).hProcess = process_handle;
            (*lp_process_information).hThread = thread_handle;
            (*lp_process_information).dwProcessId =
                winapi::um::processthreadsapi::GetProcessId(process_handle);
            (*lp_process_information).dwThreadId =
                winapi::um::processthreadsapi::GetThreadId(thread_handle);
            winapi::um::processthreadsapi::ResumeThread(thread_handle);
            (*lp_process_information).dwProcessId
        }
    } else {
        // unsafe {
        //     winapi::um::wincon::FreeConsole();
        //     //debug
        //     winapi::um::consoleapi::AllocConsole();
        //     winapi::um::processenv::SetStdHandle(
        //         winapi::um::winbase::STD_INPUT_HANDLE,
        //         winapi::um::processenv::GetStdHandle(winapi::um::winbase::STD_INPUT_HANDLE),
        //     );
        //     winapi::um::processenv::SetStdHandle(
        //         winapi::um::winbase::STD_OUTPUT_HANDLE,
        //         winapi::um::processenv::GetStdHandle(winapi::um::winbase::STD_OUTPUT_HANDLE),
        //     );
        //     winapi::um::processenv::SetStdHandle(
        //         winapi::um::winbase::STD_ERROR_HANDLE,
        //         winapi::um::processenv::GetStdHandle(winapi::um::winbase::STD_ERROR_HANDLE),
        //     );
        // }
        if let false = connect_csr_child() {
            crate::log!(
                error,
                "connect_csr_child error, errno: {}",
                std::io::Error::last_os_error()
            );
            // return u32::MAX;
        }
        0
    }
}

pub fn waitpid(
    lp_process_information: winapi::um::processthreadsapi::LPPROCESS_INFORMATION,
    dw_milliseconds: winapi::shared::minwindef::DWORD,
) -> winapi::shared::minwindef::DWORD {
    let mut exit_code: winapi::shared::minwindef::DWORD = 0xdeadbeef;
    unsafe {
        winapi::um::synchapi::WaitForSingleObject(
            (*lp_process_information).hProcess,
            dw_milliseconds,
        );
        winapi::um::processthreadsapi::GetExitCodeProcess(
            (*lp_process_information).hProcess,
            &mut exit_code,
        );
    };
    exit_code
}

pub fn do_create_file_mapping(
    dw_maximum_size_high: winapi::shared::minwindef::DWORD,
    dw_maximum_size_low: winapi::shared::minwindef::DWORD,
    lp_name: winapi::shared::minwindef::DWORD,
) -> winapi::shared::ntdef::HANDLE {
    let mut sec: winapi::um::minwinbase::SECURITY_ATTRIBUTES =
        winapi::um::minwinbase::SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<winapi::um::minwinbase::SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: winapi::shared::ntdef::NULL,
            bInheritHandle: 1,
        };
    let handle: winapi::shared::ntdef::HANDLE = unsafe {
        winapi::um::memoryapi::CreateFileMappingW(
            winapi::um::handleapi::INVALID_HANDLE_VALUE,
            &mut sec,
            winapi::um::winnt::PAGE_EXECUTE_READWRITE,
            dw_maximum_size_high,
            dw_maximum_size_low,
            lp_name as *const u16,
        )
    };
    match handle {
        winapi::um::handleapi::INVALID_HANDLE_VALUE => winapi::shared::ntdef::NULL,
        _ => handle,
    }
}

pub fn do_map_view_of_file_ex(
    h_file_mapping_object: winapi::shared::ntdef::HANDLE,
    dw_file_offset_high: winapi::shared::minwindef::DWORD,
    dw_file_offset_low: winapi::shared::minwindef::DWORD,
    dw_number_of_bytes_to_map: winapi::shared::basetsd::SIZE_T,
    lp_base_address: winapi::shared::ntdef::PVOID,
) -> winapi::shared::ntdef::PVOID {
    unsafe {
        winapi::um::memoryapi::MapViewOfFileEx(
            h_file_mapping_object,
            winapi::um::memoryapi::FILE_MAP_ALL_ACCESS,
            dw_file_offset_high,
            dw_file_offset_low,
            dw_number_of_bytes_to_map,
            lp_base_address,
        )
    }
}

pub fn do_terminate_process(process_handle: winapi::shared::ntdef::HANDLE, exit_code: i32) -> bool {
    !matches!(
        unsafe { ntapi::ntpsapi::NtTerminateProcess(process_handle, exit_code) },
        0
    )
}

pub fn do_close_handle(h_object: winapi::shared::ntdef::HANDLE) -> bool {
    !matches!(unsafe { winapi::um::handleapi::CloseHandle(h_object) }, 0)
}

pub fn do_unmap_view_of_file(lp_base_address: winapi::shared::ntdef::PVOID) -> bool {
    !matches!(
        unsafe { winapi::um::memoryapi::UnmapViewOfFile(lp_base_address) },
        0
    )
}

pub enum WinForkResult {
    Parent {
        child: winapi::shared::minwindef::DWORD,
    },
    Child,
}

pub enum WinWaitStatus {
    Exited(winapi::shared::minwindef::DWORD),
    Crash(winapi::shared::minwindef::DWORD),
    Timeout(winapi::shared::minwindef::DWORD),
}

pub type Handle = winapi::shared::ntdef::HANDLE;
pub type ProcessInformation = winapi::um::processthreadsapi::PROCESS_INFORMATION;
pub type Pvoid = winapi::shared::ntdef::PVOID;
pub const NULL: winapi::shared::ntdef::PVOID = winapi::shared::ntdef::NULL;

pub fn hopper_fork(
    lp_process_information: winapi::um::processthreadsapi::LPPROCESS_INFORMATION,
) -> eyre::Result<WinForkResult, crate::HopperError> {
    let pid = fork(lp_process_information);
    match pid {
        0 => Ok(WinForkResult::Child),
        u32::MAX => Err(error::HopperError::OSError {
            errno: std::io::Error::last_os_error(),
            info: "fork error".to_string(),
        }),
        _ => Ok(WinForkResult::Parent { child: pid }),
    }
}

pub fn terminate_close_child(
    process_information: winapi::um::processthreadsapi::PROCESS_INFORMATION,
) {
    if let Err(err) = hopper_terminate_process(process_information.hProcess, 0xdead) {
        crate::log!(
            error,
            "terminate_close_child: hopper_terminate_process error {:?}",
            err
        );
    }
    if let Err(err) = hopper_close_handle(process_information.hProcess) {
        crate::log!(
            error,
            "terminate_close_child: hopper_close_handle hProcess error {:?}",
            err
        );
    }
    if let Err(err) = hopper_close_handle(process_information.hThread) {
        crate::log!(
            error,
            "terminate_close_child: hopper_close_handle hThread error {:?}",
            err
        );
    }
}

pub fn close_child(process_information: winapi::um::processthreadsapi::PROCESS_INFORMATION) {
    if let Err(err) = hopper_close_handle(process_information.hProcess) {
        crate::log!(
            error,
            "close_child: hopper_close_handle hProcess error {:?}",
            err
        );
    }
    if let Err(err) = hopper_close_handle(process_information.hThread) {
        crate::log!(
            error,
            "close_child: hopper_close_handle hThread error {:?}",
            err
        );
    }
}

pub fn hopper_waitpid(
    lp_process_information: winapi::um::processthreadsapi::LPPROCESS_INFORMATION,
    dw_milliseconds: winapi::shared::minwindef::DWORD,
) -> eyre::Result<WinWaitStatus, crate::HopperError> {
    let code = waitpid(lp_process_information, dw_milliseconds);
    crate::log!(trace, "waitpid return: {}", code);
    match code {
        0 => Ok(WinWaitStatus::Exited(code)),
        0x2002 => Ok(WinWaitStatus::Exited(code)),
        0x103 => Ok(WinWaitStatus::Timeout(code)),
        0xdeadbeef => Err(error::HopperError::OSError {
            errno: std::io::Error::last_os_error(),
            info: "waitpid error".to_string(),
        }), //todo
        _ => Ok(WinWaitStatus::Crash(code)),
    }
}

pub fn hopper_terminate_process(
    process_handle: winapi::shared::ntdef::HANDLE,
    exit_code: i32,
) -> eyre::Result<bool, crate::HopperError> {
    match do_terminate_process(process_handle, exit_code) {
        true => Ok(true),
        false => Err(error::HopperError::OSError {
            errno: std::io::Error::last_os_error(),
            info: "terminate_process error".to_string(),
        }),
    }
}

pub fn hopper_close_handle(
    h_object: winapi::shared::ntdef::HANDLE,
) -> eyre::Result<bool, crate::HopperError> {
    match do_close_handle(h_object) {
        true => Ok(true),
        false => Err(error::HopperError::OSError {
            errno: std::io::Error::last_os_error(),
            info: "close_handle error".to_string(),
        }),
    }
}

pub fn hopper_create_file_mapping(
    dw_maximum_size_high: winapi::shared::minwindef::DWORD,
    dw_maximum_size_low: winapi::shared::minwindef::DWORD,
    lp_name: winapi::shared::minwindef::DWORD,
) -> eyre::Result<winapi::shared::ntdef::HANDLE, crate::HopperError> {
    let h_file_mapping_object: winapi::shared::ntdef::HANDLE =
        do_create_file_mapping(dw_maximum_size_high, dw_maximum_size_low, lp_name);
    match h_file_mapping_object {
        winapi::shared::ntdef::NULL => Err(error::HopperError::OSError {
            errno: std::io::Error::last_os_error(),
            info: "create_file_mapping error".to_string(),
        }),
        _ => Ok(h_file_mapping_object),
    }
}

pub fn hopper_map_view_of_file_ex(
    h_file_mapping_object: winapi::shared::ntdef::HANDLE,
    dw_file_offset_high: winapi::shared::minwindef::DWORD,
    dw_file_offset_low: winapi::shared::minwindef::DWORD,
    dw_number_of_bytes_to_map: winapi::shared::basetsd::SIZE_T,
    lp_base_address: winapi::shared::ntdef::PVOID,
) -> eyre::Result<winapi::shared::ntdef::PVOID, crate::HopperError> {
    let lp_base_address: winapi::shared::ntdef::PVOID = do_map_view_of_file_ex(
        h_file_mapping_object,
        dw_file_offset_high,
        dw_file_offset_low,
        dw_number_of_bytes_to_map,
        lp_base_address,
    );
    match lp_base_address {
        winapi::shared::ntdef::NULL => Err(error::HopperError::OSError {
            errno: std::io::Error::last_os_error(),
            info: "map_view_of_file_ex error".to_string(),
        }),
        _ => Ok(lp_base_address),
    }
}

pub fn hopper_unmap_view_of_file(
    lp_base_address: winapi::shared::ntdef::PVOID,
) -> eyre::Result<bool, crate::HopperError> {
    match do_unmap_view_of_file(lp_base_address) {
        true => Ok(true),
        false => Err(error::HopperError::OSError {
            errno: std::io::Error::last_os_error(),
            info: "unmap_view_of_file error".to_string(),
        }),
    }
}

extern "system" {
    pub fn GetSystemCpuSetInformation(
        information: winapi::um::winnt::PSYSTEM_CPU_SET_INFORMATION,
        bufferlength: u32,
        returnedlength: *mut u32,
        process: winapi::shared::ntdef::HANDLE,
        flags: u32,
    ) -> bool;

    pub fn SetProcessDefaultCpuSets(
        process: winapi::shared::ntdef::HANDLE,
        cpusetids: *const u32,
        cpusetidcount: u32,
    ) -> bool;

    pub fn SetThreadSelectedCpuSets(
        thread: winapi::shared::ntdef::HANDLE,
        cpusetids: *const u32,
        cpusetidcount: u32,
    ) -> bool;
}

pub fn get_cpu_num() -> usize {
    unsafe {
        let mut info: winapi::um::sysinfoapi::SYSTEM_INFO = std::mem::zeroed();
        winapi::um::sysinfoapi::GetSystemInfo(&mut info);
        info.dwNumberOfProcessors as usize
    }
}

pub fn get_cpu_id() -> Vec<u32> {
    let cpu_num: usize = get_cpu_num();
    let buf_len = std::mem::size_of::<winapi::um::winnt::SYSTEM_CPU_SET_INFORMATION>() * cpu_num;
    let mut ids: Vec<u32> = Vec::new();
    let mut ret_len: u32 = 0;
    let mut infos: Vec<std::mem::MaybeUninit<winapi::um::winnt::SYSTEM_CPU_SET_INFORMATION>> =
        Vec::with_capacity(cpu_num);
    unsafe {
        infos.set_len(cpu_num);
        GetSystemCpuSetInformation(
            infos.as_ptr() as *mut winapi::um::winnt::SYSTEM_CPU_SET_INFORMATION,
            buf_len as u32,
            &mut ret_len,
            winapi::um::processthreadsapi::GetCurrentProcess(),
            0,
        );
    }
    for info in infos.iter() {
        ids.push(unsafe { info.assume_init() }.CpuSet.Id);
    }
    ids
}

pub struct CpuInfo {
    _index: usize,
    usage: f32,
    id: u32,
}

pub fn get_cpu_info() -> Vec<CpuInfo> {
    let cpu_num: usize = get_cpu_num();
    println!("{}", cpu_num);
    let mut infos: Vec<
        std::mem::MaybeUninit<ntapi::ntexapi::SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION>,
    > = Vec::with_capacity(cpu_num);
    unsafe { infos.set_len(cpu_num) };
    let ids: Vec<u32> = get_cpu_id();
    let mut cpu_infos: Vec<CpuInfo> = Vec::new();
    for (i, id) in ids.iter().enumerate().take(cpu_num) {
        cpu_infos.push(CpuInfo {
            _index: i,
            usage: 0.0,
            id: *id,
        });
    }
    let len: u32 = (cpu_num
        * std::mem::size_of::<ntapi::ntexapi::SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION>())
        as u32;
    for (i, info) in cpu_infos.iter_mut().enumerate().take(cpu_num) {
        let mut cur_idle: i64 = 0;
        let mut cur_ker: i64 = 0;
        let mut cur_user: i64 = 0;
        let mut prev_idle: i64 = cur_idle;
        let mut prev_ker: i64 = cur_ker;
        let mut prev_user: i64 = cur_user;
        let mut usage: f32 = 0.0;
        while usage == 0.0 {
            unsafe {
                ntapi::ntexapi::NtQuerySystemInformation(
                    ntapi::ntexapi::SystemProcessorPerformanceInformation,
                    infos.as_ptr() as *mut winapi::ctypes::c_void,
                    len,
                    std::ptr::null_mut::<u32>(),
                );
                cur_idle = infos[i].assume_init().IdleTime.QuadPart().abs();
                cur_ker = infos[i].assume_init().KernelTime.QuadPart().abs();
                cur_user = infos[i].assume_init().UserTime.QuadPart().abs();
            }
            let delta_idle = cur_idle - prev_idle;
            let delta_kernel = cur_ker - prev_ker;
            let delta_user = cur_user - prev_user;
            if prev_idle != 0 {
                let total = delta_kernel + delta_user;
                let cur_use = (delta_kernel - delta_idle + delta_user) as f32;
                usage = std::ops::Div::div(cur_use, total as f32);
                println!("{}", usage);
            }
            prev_idle = cur_idle;
            prev_ker = cur_ker;
            prev_user = cur_user;
            let millis = std::time::Duration::from_millis(100);
            std::thread::sleep(millis);
        }
        info.usage = usage;
    }
    cpu_infos.sort_by(|a, b| {
        a.usage
            .partial_cmp(&b.usage)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    cpu_infos
}

pub fn bind_cur_process_to_one_core(id: u32) -> bool {
    let mut ids: Vec<u32> = Vec::new();
    ids.push(id);
    unsafe {
        SetProcessDefaultCpuSets(
            winapi::um::processthreadsapi::GetCurrentProcess(),
            ids.as_ptr() as *const u32,
            1,
        )
    }
}

pub fn bind_cur_thread_to_one_core(id: u32) -> bool {
    let mut ids: Vec<u32> = Vec::new();
    ids.push(id);
    unsafe {
        SetThreadSelectedCpuSets(
            winapi::um::processthreadsapi::GetCurrentThread(),
            ids.as_ptr() as *const u32,
            1,
        )
    }
}

pub fn bind_cpu_win() -> eyre::Result<(), crate::HopperError> {
    if let Ok(enable) = std::env::var(crate::config::HOPPER_ENABLE_CPU_BINDING_VAR) {
        if enable != "1" {
            return Ok(());
        }
    } else {
        return Ok(());
    }
    let cpu_info: Vec<CpuInfo> = get_cpu_info();
    let id = cpu_info[0].id;
    let index = cpu_info[0]._index;
    crate::log!(info, "bind_cpu {}, index: {}", id, index);
    if let false = bind_cur_process_to_one_core(id) {
        return Err(error::HopperError::OSError {
            errno: std::io::Error::last_os_error(),
            info: format!("bind_cur_process_to_one_core {} error", id),
        });
    }
    if let false = bind_cur_thread_to_one_core(id) {
        return Err(error::HopperError::OSError {
            errno: std::io::Error::last_os_error(),
            info: format!("bind_cur_thread_to_core {} error", id),
        });
    }
    Ok(())
}

pub fn creat_event(event_str: String) -> winapi::shared::ntdef::HANDLE {
    let mut sec: winapi::um::minwinbase::SECURITY_ATTRIBUTES =
        winapi::um::minwinbase::SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<winapi::um::minwinbase::SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: winapi::shared::ntdef::NULL,
            bInheritHandle: 1,
        };
    unsafe { winapi::um::synchapi::CreateEventA(&mut sec, 1, 0, event_str.as_ptr() as *const i8) }
}

#[allow(clippy::missing_safety_doc)]
pub unsafe fn create_thread(
    fun: winapi::um::minwinbase::LPTHREAD_START_ROUTINE,
    args: *mut winapi::ctypes::c_void,
) -> (winapi::shared::ntdef::HANDLE, u32) {
    let mut sec: winapi::um::minwinbase::SECURITY_ATTRIBUTES =
        winapi::um::minwinbase::SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<winapi::um::minwinbase::SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: winapi::shared::ntdef::NULL,
            bInheritHandle: 1,
        };
    let mut id: u32 = 0;
    let h = winapi::um::processthreadsapi::CreateThread(
        &mut sec,
        0,
        fun,
        args,
        winapi::um::winbase::CREATE_SUSPENDED,
        &mut id,
    );

    (h, id)
}
