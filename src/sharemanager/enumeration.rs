use std::io::Read;
use winapi::um::winnt::*;
use winapi::ctypes::*;
use winapi::shared::minwindef::DWORD;
use winapi::um::errhandlingapi::*;
use winapi::um::handleapi::*;
use winapi::um::memoryapi::*;
use winapi::um::processthreadsapi::*;
use winapi::um::securitybaseapi::*;
use crate::utils::parse_structure_from_memory;
use winapi::um::winbase::*;
use winapi::shared::sddl::*;
use crate::processmanager::enumeration::readunicodestringfrommemory;
use std::collections::*;
use winapi::um::fileapi::ReadFile;
use winapi::um::synchapi::WaitForSingleObject;
use crate::os::runfile;
use winapi::um::lmshare::*;
use winapi::shared::lmcons::*;
use winapi::um::lmapibuf::*;

pub struct shareenumeration{

    sharenames: Vec<String>,
    servername: String
}


impl shareenumeration{

    pub fn getshares(servername: &str) -> Result<Self,String>{

        let mut sharenames : Vec<String> = Vec::new();
        let mut sname = 0 as *mut u16;
        if servername==""{
            sname = std::ptr::null_mut();
        }
        else{
            let mut v  = servername.encode_utf16().collect::<Vec<u16>>();
            v.push(0);
            sname = v.as_mut_ptr() as *mut u16;
        }


        let mut bufferptr = 0 as *mut u8;
        let mut entriesread = 0;
        let mut totalentries = 0;
        let res = unsafe{NetShareEnum(sname,0,&mut bufferptr ,
        MAX_PREFERRED_LENGTH,&mut entriesread,
        &mut totalentries,std::ptr::null_mut())};

        if res!=0{
            return Err(format!("NetShareEnum failed: {}",unsafe{GetLastError()}));
        }



        for i in 0..entriesread{
            let si0 = parse_structure_from_memory::<SHARE_INFO_0>(unsafe{GetCurrentProcess()},(bufferptr as usize+(i as usize * std::mem::size_of::<SHARE_INFO_0>()))).unwrap();
            let sharename = readunicodestringfrommemory(unsafe{GetCurrentProcess()},si0.shi0_netname as *const c_void);

            sharenames.push(sharename);
        }


        unsafe{NetApiBufferFree(bufferptr as *mut c_void)};

        Ok(Self{sharenames,servername:servername.to_string()})

    }


    pub fn getsharetyperemark(&self,targetsharename: &str) -> Result<HashMap<u32, String>,String>{

        let mut result:HashMap<u32, String> = HashMap::new();
        let mut sname = 0 as *mut u16;
        if self.servername==""{
            sname = std::ptr::null_mut();
        }
        else{
            let mut v  = self.servername.encode_utf16().collect::<Vec<u16>>();
            v.push(0);
            sname = v.as_mut_ptr() as *mut u16;
        }


        let mut bufferptr = 0 as *mut u8;
        let mut entriesread = 0;
        let mut totalentries = 0;
        let res = unsafe{NetShareEnum(sname,
                                      1,&mut bufferptr ,
                                      MAX_PREFERRED_LENGTH,&mut entriesread,
                                      &mut totalentries,std::ptr::null_mut())};

        if res!=0{
            return Err(format!("NetShareEnum failed: {}",unsafe{GetLastError()}));
        }



        for i in 0..entriesread{
            let si1 = parse_structure_from_memory::<SHARE_INFO_1>(unsafe{GetCurrentProcess()},(bufferptr as usize+(i as usize * std::mem::size_of::<SHARE_INFO_1>()))).unwrap();
            let sharename = readunicodestringfrommemory(unsafe{GetCurrentProcess()},si1.shi1_netname as *const c_void);

            if sharename.to_lowercase()==targetsharename.to_lowercase(){
                let remark = readunicodestringfrommemory(unsafe{GetCurrentProcess()},si1.shi1_remark as *const c_void);

                result.insert(si1.shi1_type,remark);
            }

        }


        unsafe{NetApiBufferFree(bufferptr as *mut c_void)};

        Ok(result)

    }



    pub fn getsharepermissions(&self,targetsharename: &str) -> Result<HashMap<u32, String>,String>{

        let mut result:HashMap<u32, String> = HashMap::new();
        let mut sname = 0 as *mut u16;
        if self.servername==""{
            sname = std::ptr::null_mut();
        }
        else{
            let mut v  = self.servername.encode_utf16().collect::<Vec<u16>>();
            v.push(0);
            sname = v.as_mut_ptr() as *mut u16;
        }


        let mut bufferptr = 0 as *mut u8;
        let mut entriesread = 0;
        let mut totalentries = 0;
        let res = unsafe{NetShareEnum(sname,
                                      2,&mut bufferptr ,
                                      MAX_PREFERRED_LENGTH,&mut entriesread,
                                      &mut totalentries,std::ptr::null_mut())};

        if res!=0{
            return Err(format!("NetShareEnum failed: {}",unsafe{GetLastError()}));
        }



        for i in 0..entriesread{
            let si2 = parse_structure_from_memory::<SHARE_INFO_2>(unsafe{GetCurrentProcess()},(bufferptr as usize+(i as usize * std::mem::size_of::<SHARE_INFO_2>()))).unwrap();
            let sharename = readunicodestringfrommemory(unsafe{GetCurrentProcess()},si2.shi2_netname as *const c_void);

            if sharename.to_lowercase()==targetsharename.to_lowercase(){
                let remark = readunicodestringfrommemory(unsafe{GetCurrentProcess()},si2.shi2_remark as *const c_void);
                println!("Remark: {}",remark);

                println!("permissions: {}",si2.shi2_permissions);
                println!("max uses: {}",si2.shi2_max_uses);
                println!("current uses: {}",si2.shi2_current_uses);

                let path = readunicodestringfrommemory(unsafe{GetCurrentProcess()},si2.shi2_path as *const c_void);
                println!("path: {}",path);


                println!();

                result.insert(si2.shi2_type,remark);
            }

        }


        unsafe{NetApiBufferFree(bufferptr as *mut c_void)};

        Ok(result)

    }



    pub fn getsharenames(&self) -> Vec<String>{
        self.sharenames.clone()
    }




}



