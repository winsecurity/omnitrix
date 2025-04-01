
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

pub struct TokenInfo{
    tokenhandle: *mut c_void,
    tokenaccess: DWORD
}


impl TokenInfo{


    pub fn gettokenhandle(&self) -> *mut c_void{
        self.tokenhandle
    }

    pub fn new(prochandle: *mut c_void,access: DWORD) -> Result<Self,String>{

        let mut tokenhandle = 0 as *mut c_void;
        let res = unsafe{OpenProcessToken(prochandle,access,&mut tokenhandle)};

        if res==0{
            return Err(format!("OpenProcesstoken error: {}",unsafe{GetLastError()}));
        }

        return Ok(Self{
            tokenhandle,tokenaccess:access
        });

    }


    pub fn from_token_handle(tokenhandle:*mut c_void,access: DWORD) -> Self{
        Self{tokenhandle,tokenaccess:access}
    }


    pub fn gettokeninfo(&self,tokeninfoclass: u32) -> Result<Vec<u8>,String>{

        let mut bufsize:u32 = 0;


        let mut buffer = vec![0u8;bufsize as usize];
        let res = unsafe{GetTokenInformation(self.tokenhandle,tokeninfoclass,buffer.as_mut_ptr() as *mut c_void,buffer.len() as u32,&mut bufsize)};


        let mut buffer = vec![0u8;bufsize as usize];
        let res = unsafe{GetTokenInformation(self.tokenhandle,tokeninfoclass,buffer.as_mut_ptr() as *mut c_void,buffer.len() as u32,&mut bufsize)};

        if res==0{
            return Err(format!("GetTokenInformation failed: {}",unsafe{GetLastError()}));
        }


        Ok(buffer)



    }


    pub fn sidtousername(&self,psid: PSID) -> Result<String,String>{


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

    pub fn sidtousernamew(&self,psid: PSID) -> Result<String,String>{


        let mut namelength:u32 = 0;
        let mut name = vec![0u16;namelength as usize];

        let mut domainnamelength:u32 = 0;
        let mut domainname = vec![0u16; domainnamelength as usize];

        let mut typeofaccount = 0 ;

        let res = unsafe{LookupAccountSidW(std::ptr::null_mut(), psid,
                                           name.as_mut_ptr() as *mut u16, &mut namelength,
                                           domainname.as_mut_ptr() as *mut u16, &mut domainnamelength,
                                           &mut typeofaccount )};


        let mut name = vec![0u16;namelength as usize];
        let mut domainname = vec![0u16; domainnamelength as usize];

        let res = unsafe{LookupAccountSidW(std::ptr::null_mut(), psid,
                                           name.as_mut_ptr() as *mut u16, &mut namelength,
                                           domainname.as_mut_ptr() as *mut u16, &mut domainnamelength,
                                           &mut typeofaccount as *mut _ as  *mut SID_NAME_USE)};

        if res==0{
            return Err(format!("LookupAccountSidW error: {}",unsafe{GetLastError()}));

        }


        let name = String::from_utf16_lossy(&name).to_string().trim_end_matches("\0").to_string();
        let domainname = String::from_utf16_lossy(&domainname).to_string().trim_end_matches("\0").to_string();

        let fullname = domainname + "\\" + &name;
        Ok(fullname)


    }


    pub fn sidtostringsid(&self, psid: PSID) -> Result<String,String>{


        let mut base = 0 as *mut u16;
        let res = unsafe{ConvertSidToStringSidW(psid, &mut base )};

        if res==0{
            return Err(format!("ConvertSidToStringSidW error: {}",unsafe{GetLastError()}));

        }

        let stringsid = readunicodestringfrommemory(unsafe{GetCurrentProcess()},base as *const c_void);

        //println!("{}",stringsid);
        unsafe{LocalFree(std::mem::transmute(base))};

        Ok(stringsid)

    }


    pub fn luidtoprivilegename(&self,pluid: PLUID) -> Result<String,String>{

        let mut buffer = vec![0u16;2048];
        let mut reqlength: u32 = buffer.len() as u32;

        let res = unsafe{LookupPrivilegeNameW(std::ptr::null_mut(),
        pluid,buffer.as_mut_ptr() as *mut u16,&mut reqlength)};

        if res==0{
            return Err(format!("LookupPrivilegeNameW error: {}",unsafe{GetLastError()}));

        }

        let privname = readunicodestringfrommemory(unsafe{GetCurrentProcess()},buffer.as_ptr() as *const c_void);

        Ok(privname)
    }



    pub fn privilegenametoluid(&self,privname:&str) -> Result<LUID,String>{

        let mut buffer = privname.bytes().collect::<Vec<u8>>();
        buffer.push(0);

        let mut luid= unsafe{std::mem::zeroed::<LUID>()};
        let res = unsafe{LookupPrivilegeValueA(std::ptr::null_mut(),
        buffer.as_ptr() as *const i8,
        &mut luid)};

        if res==0{
            return Err(format!("LookupPrivilegeValueA failed: {}",unsafe{GetLastError()}));
        }

        Ok(luid)


    }

    pub fn gettokenprivilegedescription(&self){

        let privname = "SeRemoteShutdownPrivilege".encode_utf16().collect::<Vec<u16>>();



    }





    pub fn gettokenuser(&self) -> Result<String,String>{

        let tokenuser = self.gettokeninfo(1).unwrap();

        let tokenuser = parse_structure_from_memory::<TOKEN_USER>(unsafe{GetCurrentProcess()},tokenuser.as_ptr() as usize).unwrap();

        let username = self.sidtousernamew(tokenuser.User.Sid);

        username


    }


    pub fn gettokenusersid(&self) -> Result<String,String>{


        let tokenuser = self.gettokeninfo(1).unwrap();

        let tokenuser = parse_structure_from_memory::<TOKEN_USER>(unsafe{GetCurrentProcess()},tokenuser.as_ptr() as usize).unwrap();

        self.sidtostringsid(tokenuser.User.Sid)

    }




    pub fn gettokengroups(&self) -> HashMap<String,u32>{

        let groups = self.gettokeninfo(2).unwrap();

        let mut groupnames:HashMap<String,u32> = HashMap::new();

        let groupcount = unsafe{std::ptr::read(groups.as_ptr() as *const u32)};

        for i in 0..groupcount{
           let sidattr =  parse_structure_from_memory::<SID_AND_ATTRIBUTES>(unsafe{GetCurrentProcess()},
                                        (groups.as_ptr() as usize + (8+(i as usize*std::mem::size_of::<SID_AND_ATTRIBUTES>())))).unwrap();

            let groupname = self.sidtousernamew(sidattr.Sid).unwrap();
            groupnames.insert(groupname,sidattr.Attributes);

        }

        groupnames

    }



    pub fn gettokenprivileges(&self) -> HashMap<String,u32>{

        let privs = self.gettokeninfo(3).unwrap();

        let mut privnames:HashMap<String,u32> = HashMap::new();

        let privcount = unsafe{std::ptr::read(privs.as_ptr() as *const u32)};

        for i in 0..privcount{
            let mut luid1 =  parse_structure_from_memory::<LUID_AND_ATTRIBUTES>(unsafe{GetCurrentProcess()},
                                                                             (privs.as_ptr() as usize + (4+(i as usize*std::mem::size_of::<LUID_AND_ATTRIBUTES>())))).unwrap();


            let privname = self.luidtoprivilegename(&mut luid1.Luid ).unwrap();
            privnames.insert(privname,luid1.Attributes);

        }

        privnames

    }




    pub fn gettokentype(&self) -> u32{

        let tokeninfo = self.gettokeninfo(8).unwrap();

        let type1 = u32::from_ne_bytes(tokeninfo.try_into().unwrap());

        type1


    }


    pub fn enableprivilege(&self,privname:&str) -> Result<bool,String>{

        let luid1 = self.privilegenametoluid(privname).unwrap();

        let mut newprivs = unsafe{std::mem::zeroed::<TOKEN_PRIVILEGES>()};
        newprivs.PrivilegeCount = 1;
        newprivs.Privileges[0].Luid = luid1;
        newprivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        let mut oldprivs = unsafe{std::mem::zeroed::<TOKEN_PRIVILEGES>()};


        let mut reqlength = 0;
        let res = unsafe{AdjustTokenPrivileges(self.tokenhandle,
        0,&mut newprivs,
        std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
        &mut oldprivs,&mut reqlength)};



        if res==0{
            return Err(format!("AdjustTokenPrivileges error: {}",unsafe{GetLastError()}));
        }


        Ok(true)


    }



    pub fn removegroup(&self,gname:&str) -> Result<bool,String>{

        let groups = self.gettokeninfo(2).unwrap();



        let groupcount = unsafe{std::ptr::read(groups.as_ptr() as *const u32)};

        for i in 0..groupcount{

            let mut sidattr =  parse_structure_from_memory::<SID_AND_ATTRIBUTES>(unsafe{GetCurrentProcess()},
                                                                             (groups.as_ptr() as usize + (8+(i as usize*std::mem::size_of::<SID_AND_ATTRIBUTES>())))).unwrap();

            let groupname = self.sidtousernamew(sidattr.Sid).unwrap();

            if groupname.to_lowercase()==gname.to_lowercase(){

                /*let mut targetgroup = unsafe{std::mem::zeroed::<TOKEN_GROUPS>()};
                targetgroup.GroupCount = 1;
                targetgroup.Groups[0].Sid = sidattr.Sid;
                targetgroup.Groups[0].Attributes = SE_GROUP_USE_FOR_DENY_ONLY;

                let res = unsafe{AdjustTokenGroups(self.tokenhandle,
                0,&mut targetgroup,0,
                std::ptr::null_mut(),std::ptr::null_mut())};*/


                let mut newtokenhandle = 0 as *mut c_void;
               let res = unsafe{CreateRestrictedToken(self.tokenhandle,
               SANDBOX_INERT,
               1,&mut sidattr,
               0,std::ptr::null_mut(),
                                                      0,std::ptr::null_mut(),
               &mut newtokenhandle)};


                if res==0{
                    println!("createrestrictedtoken failed: {}",unsafe{GetLastError()});
                }

                let r = TokenInfo::from_token_handle(newtokenhandle,TOKEN_ALL_ACCESS);
                println!("{:?}",self.gettokengroups());
                println!("");
                println!("{:?}",r.gettokengroups());




                /*println!("Checking token membership");


                let mut ismember = 0;
                let res = unsafe{CheckTokenMembership(self.tokenhandle,
                sidattr.Sid,&mut ismember)};
                println!("{}",ismember);


                if ismember==SE_GROUP_ENABLED as i32{
                    println!("has memberhsip");
                }*/

            }


        }

        Ok(true)

    }


    fn switchtokenhandle(&self,newtokenhandle: *mut c_void) -> Self{
        unsafe{CloseHandle(self.tokenhandle)};

        Self{tokenhandle:newtokenhandle,tokenaccess:TOKEN_ALL_ACCESS}

    }


    fn drop(&mut self){
        if self.tokenhandle!=0 as *mut c_void{
            unsafe{CloseHandle(self.tokenhandle)};
        }
    }



}




