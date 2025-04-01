
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
use winapi::um::accctrl::*;



pub fn allocatesid() {


    let mut sidauthority = unsafe{std::mem::zeroed::<SID_IDENTIFIER_AUTHORITY>()};
    sidauthority.Value = SECURITY_WORLD_SID_AUTHORITY;

    let mut sid = 0 as  PSID;
    unsafe{AllocateAndInitializeSid(&mut sidauthority,
    1,
    SECURITY_WORLD_RID,
                                    0,0,0,0,0,0,0,
    &mut sid as *mut _ as *mut PSID)};

    println!("{:x?}",sid);

    let username = sidtousername(unsafe{sid}).unwrap();
    println!("{}",username);


    let mut ea = unsafe{std::mem::zeroed::<EXPLICIT_ACCESSA>()};
    ea.grfAccessMode = GRANT_ACCESS;
    ea.grfAccessPermissions = GENERIC_ALL;







    unsafe{FreeSid(unsafe{sid})};

}






pub fn sidtousername(psid: PSID) -> Result<String,String>{


    let mut namelength:u32 = 0;
    let mut name = vec![0i8;namelength as usize];

    let mut domainnamelength:u32 = 0;
    let mut domainname = vec![0i8; domainnamelength as usize];

    let mut typeofaccount = 0 ;

    let res = unsafe{LookupAccountSidA(std::ptr::null_mut(), psid,
                                       name.as_mut_ptr() as *mut i8, &mut namelength,
                                       domainname.as_mut_ptr() as *mut i8, &mut domainnamelength,
                                       &mut typeofaccount )};


    let mut name = vec![0u8;namelength as usize];
    let mut domainname = vec![0u8; domainnamelength as usize];

    let res = unsafe{LookupAccountSidA(std::ptr::null_mut(), psid,
                                       name.as_mut_ptr() as *mut i8, &mut namelength,
                                       domainname.as_mut_ptr() as *mut i8, &mut domainnamelength,
                                       &mut typeofaccount as *mut _ as  *mut SID_NAME_USE)};

    if res==0{
        return Err(format!("LookupAccountSidA error: {}",unsafe{GetLastError()}));

    }


    let name = String::from_utf8_lossy(&name).to_string().trim_end_matches("\0").to_string();
    let domainname = String::from_utf8_lossy(&domainname).to_string().trim_end_matches("\0").to_string();

    let fullname = domainname + "\\" + &name;
    Ok(fullname)


}
