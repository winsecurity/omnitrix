use winapi::um::memoryapi::{ReadProcessMemory, VirtualAlloc, VirtualAllocEx, VirtualProtectEx, WriteProcessMemory};
use winapi::um::minwinbase::OVERLAPPED;
use winapi::um::processthreadsapi::*;
use winapi::um::winnt::*;
use winapi::um::synchapi::*;
use winapi::ctypes::*;
use crate::utils::parse_structure_from_memory;
use ntapi::ntpsapi::*;
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
use winapi::um::errhandlingapi::*;
use winapi::um::handleapi::*;
use winapi::um::memoryapi::*;
use winapi::um::processthreadsapi::*;
use winapi::um::securitybaseapi::*;
use winapi::um::winbase::*;



pub struct fivebytehook{

    dllname: String,
    funcnametohook: String,
    ogaddr: usize,
    ogbytes: Vec<u8>,
    hookedfuncaddress: usize 

}


impl fivebytehook{

    pub fn new(dllname: String, funcnametohook: String, hookedfuncaddress:usize) -> Self{

        Self{dllname,funcnametohook,hookedfuncaddress, ogaddr:0, ogbytes:vec![0u8;5]}

    }


    pub fn install_hook(&mut self){

        let mut dll = self.dllname.bytes().collect::<Vec<u8>>();
        dll.push(0);

        let dllhandle = unsafe{LoadLibraryA(dll.as_ptr() as *const i8)};


        let mut func = self.funcnametohook.bytes().collect::<Vec<u8>>();
        func.push(0);

        unsafe{ self.ogaddr = GetProcAddress(dllhandle,func.as_ptr() as *const i8) as usize};
    
        let offset = unsafe{ self.hookedfuncaddress - (self.ogaddr  + 5)};
        
    
        let mut bytesread = 0;
        unsafe{ReadProcessMemory(GetCurrentProcess(), 
            self.ogaddr as *const c_void, 
            self.ogbytes.as_mut_ptr() as *mut c_void, 
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
        self.ogaddr as *mut c_void,jmp.as_ptr() as *const c_void,jmp.len(),std::ptr::null_mut())};
    

    }


    pub fn uninstall_hook(&mut self){

         // restoring those 5 bytes
         let mut byteswritten = 0;
         unsafe{WriteProcessMemory(GetCurrentProcess(), 
         self.ogaddr as *mut c_void, 
         self.ogbytes.as_ptr() as *const c_void, 
         self.ogbytes.len(), &mut byteswritten)};

    }

    pub fn getogaddr(&self) -> usize{
        self.ogaddr
    }

}

