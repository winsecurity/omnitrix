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

use crate::peparser::*;

pub struct iathook{
    dllname: String,
    funcnametohook: String,
    maliciousfuncaddress: usize,
    ogfuncaddress: usize,
    destinationaddresstowrite: usize
}

impl iathook{


    pub fn new(dllname: String, funcnametohook: String, maliciousfuncaddress: usize) -> Self{

        Self{dllname,funcnametohook,maliciousfuncaddress,destinationaddresstowrite:0,ogfuncaddress:0}
    
    }


    pub fn install_hook(&mut self){

        let mut dll = self.dllname.bytes().collect::<Vec<u8>>();
        dll.push(0);

        let dllhandle = unsafe{LoadLibraryA(dll.as_ptr() as *const i8)};

        //let ogaddr = unsafe{GetProcAddress(dllhandle, "ReadProcessMemory\0".as_bytes().as_ptr() as *const i8)};
        //println!("og addr: {:x?}",ogaddr);

        let pebase = self.get_process_baseaddress(unsafe{GetCurrentProcessId()}).unwrap();
        let pe = Peparser64::parse_from_memory(unsafe{GetCurrentProcessId()}, pebase).unwrap();

        let imports = pe.get_imports();

        for i in 0..imports.len(){
            if imports[i].dllname.to_lowercase() == self.dllname.to_lowercase(){

                for (funcname,funcoffset) in &imports[i].functions{
                    if funcname.to_lowercase()==self.funcnametohook.to_lowercase(){

                       // println!("funcname: {}",funcname);
                        //println!("funcoffset: {:x?}",funcoffset);

                        
                        self.ogfuncaddress = unsafe{std::ptr::read((pebase+funcoffset) as *const usize)} ;
                        
                        // writing malicious function address at pebase + funcoffset
                        self.destinationaddresstowrite = pebase + (*funcoffset) as usize;
                        
                        let mut oldprotect = 0;
                        unsafe{VirtualProtect(self.destinationaddresstowrite as *mut c_void, 
                            8, PAGE_EXECUTE_READWRITE, &mut oldprotect)};

                        let malbytes = self.maliciousfuncaddress.to_ne_bytes();
                        unsafe{WriteProcessMemory(GetCurrentProcess(), 
                            self.destinationaddresstowrite as *mut c_void, 
                            malbytes.as_ptr() as *const c_void, 
                            malbytes.len(), std::ptr::null_mut())};

                    }

                }

            }
        }

    }



    pub fn uninstall_hook(&mut self){

        let ogbytes = self.ogfuncaddress.to_ne_bytes();
                        unsafe{WriteProcessMemory(GetCurrentProcess(), 
                            self.destinationaddresstowrite as *mut c_void, 
                            ogbytes.as_ptr() as *const c_void, 
                            ogbytes.len(), std::ptr::null_mut())};

    }


    fn get_process_baseaddress(&self,pid:u32) -> Result<usize,String>{
        let prochandle = unsafe{OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION,0,pid)};
        if prochandle.is_null(){
             return Err(format!("openprocess failed: {}",unsafe{GetLastError()}));
        }

        let mut buffer = vec![0u8;std::mem::size_of::<PROCESS_BASIC_INFORMATION>()];

        let mut reqlength = 0;
        let ntstatus = unsafe{NtQueryInformationProcess(prochandle,0,
            buffer.as_mut_ptr() as *mut c_void,buffer.len() as u32,&mut reqlength)};

       
        if NT_SUCCESS(ntstatus){
            let pbi = parse_structure_from_memory::<PROCESS_BASIC_INFORMATION>(unsafe{GetCurrentProcess()},buffer.as_ptr() as usize).unwrap();
            let peb = parse_structure_from_memory::<PEB>(prochandle, pbi.PebBaseAddress as usize).unwrap();
           
            unsafe{CloseHandle(prochandle)};



            Ok(peb.ImageBaseAddress as usize)
        }

       else{
            unsafe{CloseHandle(prochandle)};

           Err(format!("unable to get peb addresss"))
       }
    }


    pub fn getogaddr(&self) -> usize{
        self.ogfuncaddress
    }


}
