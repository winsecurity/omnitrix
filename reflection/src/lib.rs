use std::arch::asm;
use ntapi::ntldr::LDR_DATA_TABLE_ENTRY;
use ntapi::ntpebteb::*;
use ntapi::ntpsapi::PEB_LDR_DATA;
use winapi::ctypes::*;
use winapi::shared::minwindef::*;
use winapi::shared::windef::HWND;
use winapi::um::memoryapi::{VirtualAlloc, WriteProcessMemory};
use winapi::um::processthreadsapi::*;
use winapi::um::winnt::*;
use winapi::um::winuser::MessageBoxA;

mod utils;
mod peparser;
mod processmanager;

use utils::*;
use processmanager::*;



#[no_mangle]
pub unsafe extern "C" fn myloader(){


    let mut ppeb = get_self_peb();


    let kernel32base = get_dll_base_address_from_peb(ppeb as usize,"KERNEL32");
    if kernel32base != 0 {

        let virtualallocaddr = get_dll_raw_export_function(kernel32base,"VirtualAlloc");

        let user32dll = get_dll_base_address_from_peb(ppeb as usize ,"USER32.dll");

        let msgboxaddr = get_dll_raw_export_function(user32dll,"MessageBoxA");


        let virtuallocrunner = core::mem::transmute::<usize,
            fn(LPVOID,usize,u32,u32) -> LPVOID
        >(virtualallocaddr);

        let base = virtuallocrunner(core::ptr::null_mut(),10,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);


        core::ptr::write(base as *mut [u8;4],[0x61,0x62,0x63,0x64]);

        let msgbox = core::mem::transmute::<usize,
            fn(HWND,LPCSTR,LPCSTR,u32) -> u32
        >(msgboxaddr);



        msgbox(core::ptr::null_mut(),base as *mut i8,
              base as *mut i8,0);




    }



}


pub unsafe fn get_dll_base_address_from_peb(pebaddress: usize,dllname:&str) -> usize{


    let peb = *(pebaddress as *mut PEB);

    let pimagebase = peb.ImageBaseAddress;

    let ldr = (*peb.Ldr) ;

    let mut firstentry = (* ldr.InLoadOrderModuleList.Flink);

    // firstentry -> Flink = ldr_data_table_entry

    let mut msgboxaddress: u64 = 0;

    loop{

        if firstentry.Flink as usize==(peb.Ldr as usize+ 0x10){
            break;
        }

        let tableentry = ( *((firstentry.Flink) as *mut LDR_DATA_TABLE_ENTRY)  );

        let dllnamebuffer = tableentry.BaseDllName.Buffer;

        // unicode buffer
        if cmp_unicode_string_at_memory(dllnamebuffer as usize,dllname){

            return tableentry.DllBase as usize;


        }


        firstentry = tableentry.InLoadOrderLinks;

    }

    0

}

pub unsafe fn get_dll_raw_export_function(dllbase:usize,functionname:&str) -> usize{

    // we found our dllbase

    // now we need to parse pe file
    let dosheader = *(dllbase as *const IMAGE_DOS_HEADER);

    let ntheader = *((dllbase as usize + dosheader.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);

    let exportoffset = (dllbase as usize ) + ntheader.OptionalHeader.DataDirectory[0].VirtualAddress as usize;

    let exports = *(exportoffset as *mut IMAGE_EXPORT_DIRECTORY);

    let eatptr = (dllbase as usize) + exports.AddressOfFunctions as usize;
    let entptr = (dllbase as usize) + exports.AddressOfNames as usize;
    let eotptr = (dllbase as usize) + exports.AddressOfNameOrdinals as usize;

    for i in 0 .. exports.NumberOfNames{

        let funcnameoffset = *(((entptr) + (i as usize*4) ) as *const u32);

        let result =  cmp_string_at_memory(dllbase as usize+funcnameoffset as usize,functionname);


        if result==true{


            // read the exact index value at ordinal array
            let funcindex =  *((eotptr + (i as usize*2)) as *const u16);

            // now read address rva 4 bytes at funcindex of eatarray
            let funcoffset= *((eatptr + (funcindex as usize*4)) as *const u32);



            return (dllbase as usize+funcoffset as usize);

            let msgbox = core::mem::transmute::<usize,
                fn(HWND,LPCSTR,LPCSTR,u32) -> u32
            >(dllbase as usize+funcoffset as usize);



            msgbox(core::ptr::null_mut(),"hi\0".as_bytes().as_ptr() as *mut i8,
                   "hi\0".as_bytes().as_ptr() as *mut i8,0);

        }



    }


    return 0;
}



pub fn cmp_string_at_memory(memoryaddress: usize, s:&str) -> bool{

    let mut i=0 as usize;
    let a = s.as_bytes();
    let mut ismatch = true;
    loop{

        if i==s.len(){
            break;
        }

       let v = unsafe{ *((memoryaddress + i)as *const u8) };


        if v!=a[i]{
            ismatch = false;
            break;
        }

        i = i+1;
    }

    ismatch

}


pub fn cmp_unicode_string_at_memory(memoryaddress: usize, s:&str) -> bool{
    let mut i=0 as usize;
    let a = s.as_bytes();
    let mut ismatch = true;

    loop{

        if i==s.len(){
            break;
        }

        let v = unsafe{ *((memoryaddress + i*2)as *const u8) };


        if v!=a[i]{
            ismatch = false;
            break;
        }

        i = i+1;
    }

    ismatch

}

pub fn get_self_peb() -> u64{

    let mut a: u64 = 0;


    unsafe{asm!(
    "mov {}, gs:[0x60]",
    out(reg) a,


    );}

    a

}
