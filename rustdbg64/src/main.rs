use winapi::um::errhandlingapi::GetLastError;
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
use winapi::um::memoryapi::*;
use winapi::um::processthreadsapi::*;
use winapi::um::winnt::*;
use winapi::ctypes::*;
use winapi::um::winbase::{CREATE_NEW_CONSOLE, DEBUG_ONLY_THIS_PROCESS};
use crate::debugger::query_memory_basic_information;
use crate::process_manager::enumeration::get_processes;

mod debugger;
mod utils;
mod process_manager;
mod peparser;

fn main() {


    /*let args = std::env::args().collect::<Vec<String>>();

    if args.len()!=2{
        std::process::exit(0);
    }*/

    //unsafe{LoadLibraryA("user32.dll\0".as_bytes().as_ptr() as *const i8)};

    let ntdll = unsafe{GetModuleHandleA("ntdll.dll\0".as_bytes().as_ptr() as *const i8)};
    //println!("ntdll.dll is at baseaddress: {:x?}",ntdll);
    let amsiscanbufferaddress = unsafe{GetProcAddress(ntdll,"LdrLoadDll\0".as_bytes().as_ptr() as *const i8)};


    //println!("LdrLoadDll is at baseaddress: {:x?}",amsiscanbufferaddress);

    /*let mbi = query_memory_basic_information(unsafe{GetCurrentProcess()},amsiscanbufferaddress as *const c_void).unwrap();

    println!("base: {:x?}",mbi.BaseAddress);
    println!("allocationbase: {:x?}",mbi.AllocationBase);
    println!("allocationprotect: {:x?}",mbi.AllocationProtect);
    println!("regionsize: {:x?}",mbi.RegionSize);
    println!("state: {:x?}",mbi.State);
    println!("protect: {:x?}",mbi.Protect);*/

    //"C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    // "E:\\rust_practice\\omnitrix\\target\\release\\omnitrix.exe"





    let mut dbg = debugger::debugger::launch_executable("E:\\CMDCertification-EXAM\\examchallenges\\myserver\\bin\\examprocess2.exe").unwrap();

    dbg.set_hardware_breakpoint(amsiscanbufferaddress as usize,1,0);

    dbg.continue_debug_event(dbg.get_debuggee_process_id(),dbg.get_debuggee_thread_id(),DBG_CONTINUE);


    dbg.enter_debugging_loop(amsiscanbufferaddress as usize);




    std::process::exit(0);


    let args = std::env::args().collect::<Vec<String>>();


    if args.len() == 3 || args.len() == 2 {

    }
    else{
        println!("Usage: amsibypass.exe createnew/attach [pid]");
        std::process::exit(0);
    }

    let mut pid = 0;


    if args[1].to_lowercase()=="createnew"{

        // creating new powershell process

        let mut pi = unsafe{std::mem::zeroed::<PROCESS_INFORMATION>()};

        let mut si = unsafe{std::mem::zeroed::<STARTUPINFOA>()};
        si.cb = unsafe{std::mem::size_of::<STARTUPINFOA>()} as u32 ;


        let mut buffer = "powershell.exe".bytes().collect::<Vec<u8>>();
        buffer.push(0);

        let res = unsafe{CreateProcessA(std::ptr::null_mut(),
                             buffer.as_mut_ptr() as *mut i8,
                              std::ptr::null_mut(),
                              std::ptr::null_mut(),
        0,CREATE_NEW_CONSOLE,std::ptr::null_mut(),
                              std::ptr::null_mut(),
        &mut si, &mut pi)};

        if res==0{
            println!("CreateProcess failed: {}",unsafe{GetLastError()});
            std::process::exit(0);
        }
        else{
            println!("new powershell process created with new pid: {}",pi.dwProcessId);
            pid = pi.dwProcessId;
            // attaching to our newly created process and start debugging
        }

    }

    else if args[1].to_lowercase()=="attach"{

        let res = args[2].parse::<u32>();
        if res.is_err(){
            println!("{}",res.unwrap_err());
            std::process::exit(0);
        }
        else{
            pid = res.unwrap();
        }

    }

    if pid==0{
        println!("cannot debug system 0 process");
        std::process::exit(0);
    }




    std::thread::sleep(std::time::Duration::from_secs(1));
    println!("[+] Trying to attach to the process: {}",pid);
    let dbg = debugger::debugger::attach_to_process(pid);
    if dbg.is_ok(){
        let mut dbg = dbg.unwrap();

        println!("[+] Attached to the process {} successfully!",dbg.get_debuggee_process_id());


        println!("[+] Enumerating all threads and getting context");

        let mut threadids = dbg.get_all_threads(dbg.get_debuggee_process_id()).unwrap();

        for i in 0..threadids.len(){
            let context = dbg.get_thread_context(threadids[i].th32ThreadID);
            if context.is_ok(){
                let context = context.unwrap();

                println!("Thread ID: {}",threadids[i].th32ThreadID);
                println!("[+] RIP register: {:x?}",context.Rip);
                println!("[+] RAX register: {:x?}",context.Rax);
                println!("[+] RSP register: {:x?}",context.Rsp);
                println!("[+] RBP register: {:x?}",context.Rbp );
                println!("[+] RBX register: {:x?}",context.Rbx );
                println!("[+] DR0 register: {:x?}",context.Dr0);
                println!("[+] DR1 register: {:x?}",context.Dr1);
                println!("[+] DR2 register: {:x?}",context.Dr2);
                println!("[+] DR3 register: {:x?}",context.Dr3);
                println!("[+] DR7 register: {:x?}",context.Dr7);

                println!();
            }



        }




        //unsafe{LoadLibraryA("amsi.dll\0".as_bytes().as_ptr() as *const i8)};
        let ntdll = unsafe{GetModuleHandleA("ntdll.dll\0".as_bytes().as_ptr() as *const i8)};
        println!("ntdll.dll is at baseaddress: {:x?}",ntdll);
        let amsiscanbufferaddress = unsafe{GetProcAddress(ntdll,"LdrLoadDll\0".as_bytes().as_ptr() as *const i8)};


        println!("LdrLoadDll address: {:x?}",amsiscanbufferaddress);


                /*let res = dbg.set_hardware_breakpoint(messageboxaddress as usize, 1,0);
                if res.is_err(){
                    println!("[+] Failed to set hardware breakpoint!: {}",res.unwrap_err());
                }*/
                //dbg.set_software_breakpoint(messageboxaddress as usize);

        dbg.set_hardware_breakpoint(amsiscanbufferaddress as usize,1,0);

        dbg.continue_debug_event(dbg.get_debuggee_process_id(),dbg.get_debuggee_thread_id(),DBG_CONTINUE);

        //dbg.enter_debugging_loop();


        /*println!("Enter anything to continue");
        let mut uinput = String::new();
        std::io::stdin().read_line(&mut uinput).unwrap();*/



        let res = dbg.detach();
        if res.is_ok(){
            println!("[+] Detached from the process {} successfully!",dbg.get_debuggee_process_id());
        }

    }









   // std::process::exit(0);




}

