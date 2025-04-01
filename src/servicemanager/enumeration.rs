


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
use winapi::um::winsvc::*;

pub struct serviceenumerator<'a>{
    schandle: *mut c_void,
    servername: &'a str
}


impl<'a> serviceenumerator<'a>{

    pub fn new(sname: &'a str) -> Result<Self,String>{

        let mut v = sname.encode_utf16().collect::<Vec<u16>>();
        v.push(0);

        let schandle = unsafe{OpenSCManagerW(v.as_mut_ptr() as *mut u16,
        std::ptr::null_mut(),SC_MANAGER_CONNECT|SC_MANAGER_ENUMERATE_SERVICE|SC_MANAGER_QUERY_LOCK_STATUS)};

        if schandle.is_null(){
            //println!("OpenSCManagerW failed: {}",unsafe{GetLastError()});
            return Err(format!("OpenSCManagerW failed: {}",unsafe{GetLastError()}));
        }

        Ok(Self{schandle: schandle as *mut c_void,servername:sname})


    }


    /// Returns HashMap<Displayname, servicename>
    pub fn get_servicenames(&self) -> Result<HashMap<String,String>,String>{

        let mut snames:HashMap<String,String> = HashMap::new();
        let mut bytesneeded = 0;
        let mut buffer = vec![0u8;bytesneeded as usize];
        let mut servicescount = 0;
        let res = unsafe{EnumServicesStatusW(self.schandle as SC_HANDLE,
        SERVICE_WIN32,SERVICE_STATE_ALL,
        buffer.as_mut_ptr() as *mut ENUM_SERVICE_STATUSW,0,&mut bytesneeded,
        &mut servicescount,std::ptr::null_mut())};

        if res==0&&unsafe{GetLastError()}==234{



            let mut buffer = vec![0u8;bytesneeded as usize];
            let res = unsafe{EnumServicesStatusW(self.schandle as SC_HANDLE,
                                                 SERVICE_WIN32,SERVICE_STATE_ALL,
                                                 buffer.as_mut_ptr() as *mut ENUM_SERVICE_STATUSW,buffer.len() as u32,&mut bytesneeded,
                                                 &mut servicescount,std::ptr::null_mut())};


            for i in 0..servicescount{

                let servicestatus = parse_structure_from_memory::<ENUM_SERVICE_STATUSW>(unsafe{GetCurrentProcess()},(buffer.as_ptr() as usize + (i as usize*std::mem::size_of::<ENUM_SERVICE_STATUSW>())) as usize).unwrap();

                let displayname = readunicodestringfrommemory(unsafe{GetCurrentProcess()},servicestatus.lpDisplayName as *const c_void);
                let servicename = readunicodestringfrommemory(unsafe{GetCurrentProcess()},servicestatus.lpServiceName as *const c_void);

               snames.insert(displayname,servicename);

            }





        }

        if snames.len()>0{
            Ok(snames)
        }
        else{
            Err(format!("EnumServicesStatusW failed:{}", unsafe{GetLastError()}))
        }


    }



    pub fn get_servicestatus(&self,servicetosearch: &str) -> Result<SERVICE_STATUS,String>{

        let mut snames:HashMap<String,String> = HashMap::new();
        let mut bytesneeded = 0;
        let mut buffer = vec![0u8;bytesneeded as usize];
        let mut servicescount = 0;
        let res = unsafe{EnumServicesStatusW(self.schandle as SC_HANDLE,
                                             SERVICE_WIN32,SERVICE_STATE_ALL,
                                             buffer.as_mut_ptr() as *mut ENUM_SERVICE_STATUSW,0,&mut bytesneeded,
                                             &mut servicescount,std::ptr::null_mut())};

        if res==0&&unsafe{GetLastError()}==234{



            let mut buffer = vec![0u8;bytesneeded as usize];
            let res = unsafe{EnumServicesStatusW(self.schandle as SC_HANDLE,
                                                 SERVICE_WIN32,SERVICE_STATE_ALL,
                                                 buffer.as_mut_ptr() as *mut ENUM_SERVICE_STATUSW,buffer.len() as u32,&mut bytesneeded,
                                                 &mut servicescount,std::ptr::null_mut())};


            for i in 0..servicescount{

                let servicestatus = parse_structure_from_memory::<ENUM_SERVICE_STATUSW>(unsafe{GetCurrentProcess()},(buffer.as_ptr() as usize + (i as usize*std::mem::size_of::<ENUM_SERVICE_STATUSW>())) as usize).unwrap();

                let displayname = readunicodestringfrommemory(unsafe{GetCurrentProcess()},servicestatus.lpDisplayName as *const c_void);
                let servicename = readunicodestringfrommemory(unsafe{GetCurrentProcess()},servicestatus.lpServiceName as *const c_void);

                if servicename.to_lowercase()==servicetosearch.to_lowercase(){

                    return Ok(servicestatus.ServiceStatus);

                }

            }





        }


        Err(format!("service not found or something went wrong"))

    }



    pub fn get_serviceconfig(&self, servicename: &str) -> Result<QUERY_SERVICE_CONFIGW,String>{

        let mut sname =  servicename.encode_utf16().collect::<Vec<u16>>();
        sname.push(0);

        let servicehandle = unsafe{OpenServiceW(self.schandle as SC_HANDLE,
        sname.as_mut_ptr() as *mut u16,
        GENERIC_READ)};



        if servicehandle!=std::ptr::null_mut(){
            let mut bytesneeded = 0 as u32;
            let mut buffer = vec![0u8;bytesneeded as usize];

            unsafe{QueryServiceConfigW(servicehandle ,
                                       buffer.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW,
                                       buffer.len() as u32,&mut bytesneeded)};

            buffer = vec![0u8;bytesneeded as usize];

            let res = unsafe{QueryServiceConfigW(servicehandle ,
                                                 buffer.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW,
                                                 buffer.len() as u32,&mut bytesneeded)};

            if res!=0{

               let serviceconfig=  unsafe{*(buffer.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW)};

                let servicebinarypath = readunicodestringfrommemory(unsafe{GetCurrentProcess()},serviceconfig.lpBinaryPathName as *const c_void);

                return Ok(serviceconfig);

            }

            unsafe{CloseServiceHandle(servicehandle)};
        }

        return Err(format!("unable to open service"));

    }


    pub fn get_unquotedservicepaths(&self) -> HashMap<String,String>{

        let snames = self.get_servicenames().unwrap();
        let mut paths: HashMap<String,String> = HashMap::new();
        for (displayname,servicename) in snames.iter(){


                let sconfig = self.get_serviceconfig(servicename);

                if sconfig.is_ok(){
                    let sconfig = sconfig.unwrap();
                    let binarypath = readunicodestringfrommemory(unsafe{GetCurrentProcess()},sconfig.lpBinaryPathName as *const c_void);

                    if !binarypath.contains('"'){
                        if !binarypath.to_lowercase().contains( "windows\\system32") &&
                            !binarypath.to_lowercase().contains( "windows\\syswow64") {
                            paths.insert((*servicename).clone(),binarypath);
                        }

                    }

                }



        }


        paths
    }


    pub fn get_servicedescription(&self,servicename:&str) -> Result<String, String> {
        let mut sname =  servicename.encode_utf16().collect::<Vec<u16>>();
        sname.push(0);

        let servicehandle = unsafe{OpenServiceW(self.schandle as SC_HANDLE,
                                                sname.as_mut_ptr() as *mut u16,
                                                GENERIC_READ)};



        if servicehandle!=std::ptr::null_mut(){
            let mut bytesneeded = 0 as u32;
            let mut buffer = vec![0u8;bytesneeded as usize];

            unsafe{QueryServiceConfig2W(servicehandle ,1,
                                       buffer.as_mut_ptr() ,
                                       buffer.len() as u32,&mut bytesneeded)};

            buffer = vec![0u8;bytesneeded as usize];

            let res = unsafe{QueryServiceConfig2W(servicehandle ,1,
                                                  buffer.as_mut_ptr() ,
                                                  buffer.len() as u32,&mut bytesneeded)};
            if res!=0{

                let sdescription=  unsafe{*(buffer.as_mut_ptr() as *mut SERVICE_DESCRIPTIONW)};

                let description = readunicodestringfrommemory(unsafe{GetCurrentProcess()},sdescription.lpDescription as *const c_void);

                return Ok(description);

            }

            unsafe{CloseServiceHandle(servicehandle)};
            return Err(format!("QueryServiceConfig2W failed: {}",unsafe{GetLastError()}));

        }

        return Err(format!("unable to open service"));

    }



}


impl<'a> Drop for serviceenumerator<'a>{
    fn drop(&mut self){

        if self.schandle!=0 as *mut c_void{
            //println!("closing schandle");
           unsafe{CloseServiceHandle(self.schandle as SC_HANDLE)};


        }
    }
}

