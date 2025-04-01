use winapi::um::winnt::*;
use winapi::um::winreg::*;

use std::io::Read;
use winapi::um::winnt::*;
use winapi::ctypes::*;
use winapi::shared::winerror::*;
use winapi::shared::minwindef::*;
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
use crate::utils;

pub struct registry<'a>{

    hive:HKEY,
    subkey: &'a str,
    reghandle:  HKEY
}


impl<'a> registry<'a>{

    pub fn new(hivename:&str,subkey:&'a str ) -> Result<Self,String>{

        let hive = match hivename.to_lowercase().as_str(){
            "hkey_current_user" | "hkcu" =>HKEY_CURRENT_USER,
            "hkey_classes_root" | "hkcr" => HKEY_CLASSES_ROOT,
            "hkey_local_machine" | "hklm" => HKEY_LOCAL_MACHINE,
            "hkey_users" | "hku" => HKEY_USERS,
            "hkey_current_config" | "hkcc" => HKEY_CURRENT_CONFIG,

            _ => {return Err("cannot enumerate the specified hive".to_string());}
        };


        let mut reghandle = 0 as HKEY   ;
        let res= unsafe{RegOpenKeyExA(hive,subkey.as_bytes().as_ptr() as *const i8,
        0,KEY_ALL_ACCESS,&mut reghandle as *mut _ as *mut HKEY)};

        if res!=(ERROR_SUCCESS as i32){
            //println!("reghandle: {:x?}",reghandle);

            //println!("res: {}",res);
            return Err(format!("RegOpenKeyExA failed: {}",unsafe{GetLastError()}));
        }
        //println!("reghandle: {:x?}",reghandle);

        Ok(Self{
            hive,
            subkey:subkey,
            reghandle:reghandle as  HKEY
        })

    }


    pub fn get_subkeys(&self) -> Vec<String>{

        let mut subkeys:Vec<String>  = Vec::new();

        let mut i = 0;
        loop{
            let mut subkeyname= vec![0u8;1024];
            let mut subkeynamelength = 1024;
            let mut userclass= vec![0u8;1024];
            let mut userclasslength = 1024;

            let res = unsafe{RegEnumKeyExA(self.reghandle,
                                           i,
                                           subkeyname.as_mut_ptr() as *mut i8,
                                           &mut subkeynamelength,
                                           std::ptr::null_mut(),
                                           userclass.as_mut_ptr() as *mut i8,
                                           &mut userclasslength,std::ptr::null_mut())};


            // 259 error means NO MORE DATA AVAILABLE

            if res==0{
                let subkey = String::from_utf8_lossy(&subkeyname).trim_end_matches("\0").to_string();

                subkeys.push(subkey);


            }
            else if res==259 { break; }

            i+=1;
        }

        subkeys

    }



    pub fn get_valuenamesofkey(&self) -> HashMap<String,String>{


        let mut allvalues: HashMap<String,String> = HashMap::new();
        let mut i = 0;
        loop{

            let mut valuenamebufferlength = 1024 as u32;
            let mut valuenamebuffer = vec![0u8;valuenamebufferlength as usize];
            let mut valuetype = 0u32;

            let mut databufferlength = 1024u32;
            let mut databuffer = vec![0u8;databufferlength as usize];
            let res = unsafe{RegEnumValueA(self.reghandle,
                                           i,
                                           valuenamebuffer.as_mut_ptr() as *mut i8,
                                           &mut valuenamebufferlength,
                                           std::ptr::null_mut(),
                                           &mut valuetype,
                                           databuffer.as_mut_ptr() as *mut u8,
                                           &mut databufferlength)};

            if res==0{
                let valuename = String::from_utf8_lossy(&valuenamebuffer).trim_end_matches("\0").to_string();
                match valuetype{
                    REG_SZ|REG_EXPAND_SZ|REG_MULTI_SZ=>{
                        let bufferstring = utils::ReadStringFromMemory(unsafe{GetCurrentProcess()},databuffer.as_ptr() as *const c_void);
                        allvalues.insert(valuename,bufferstring);
                    },
                    REG_DWORD =>{
                      let value = unsafe{std::ptr::read(databuffer.as_ptr() as *const u32)};
                        allvalues.insert(valuename,format!("{}",value));
                    },
                    REG_QWORD =>{
                        let value = unsafe{std::ptr::read(databuffer.as_ptr() as *const u64)};
                        allvalues.insert(valuename,format!("{}",value));
                    },

                    _ => ()
                }
            }
            else if res==ERROR_NO_MORE_ITEMS as i32{
                break;
            }


            i+=1;
        }

        allvalues
    }


    pub fn create_subkey(&self) -> Result<u8,String>{

        let mut newkeyhandle = 0 as HKEY;
        let mut disposition = 0;

        let res = unsafe{RegCreateKeyExA(self.reghandle,
        self.subkey.as_bytes().as_ptr() as *const i8,
        0,std::ptr::null_mut(),
        REG_OPTION_NON_VOLATILE,
        KEY_CREATE_SUB_KEY,std::ptr::null_mut(),
        &mut newkeyhandle ,&mut disposition)};

        // SUCCESS
        if res==0{
            match disposition{
                1=>println!("created new subkey"),
                2=>println!("opened existing subkey"),
                _ => println!("something went wrong")
            }
            unsafe{RegCloseKey(newkeyhandle)};
            Ok(0)
        }

        else{
            return Err(format!("RegCreateKeyExA failed: {}",unsafe{GetLastError()}));
        }


    }



    pub fn set_subkeyvalue(&self,valuename:&str, valuevalue:&str) -> Result<u8,String>{

        let mut valuename = valuename.bytes().collect::<Vec<u8>>();
        valuename.push(0);
        let mut valuevalue = valuevalue.bytes().collect::<Vec<u8>>();
        valuevalue.push(0);

        let res = unsafe{RegSetValueExA(self.reghandle,
        valuename.as_ptr() as *const i8,
        0,REG_SZ,
        valuevalue.as_ptr() as *const BYTE,valuevalue.len() as u32)};


        if res!=0{
            return Err(format!("RegSetValueExA failed: {}",unsafe{GetLastError()}));
        }

        Ok(0)
    }

}



impl<'a> Drop for registry<'a>{

    fn drop(&mut self){

        if self.reghandle!=0 as HKEY{
            let res = unsafe{RegCloseKey(self.reghandle)};

           // println!("regclosekey error status: {}",res);
        }

    }

}
