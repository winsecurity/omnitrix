use std::arch::asm;
use ntapi::ntldr::LDR_DATA_TABLE_ENTRY;
use ntapi::ntpebteb::*;
use ntapi::ntpsapi::PEB_LDR_DATA;
use winapi::ctypes::*;
use winapi::shared::minwindef::*;
use winapi::shared::windef::HWND;
use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};
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

    // finding our own raw dll's base address
    let mut rip = 0 as u64;
    core::arch::asm!(
    "lea {},[rip]",
    out(reg) rip
    );


    let mut ourolddllbase: usize = 0;


    loop{

        let a = *(rip as *const u8);
        let b =  *((rip as usize + 1) as *const u8);

        if a==0x4d && b==0x5a{
            // we have found our dll contents by backtracking
            ourolddllbase = rip as usize;
            break;
        }

        rip = rip-1;

    }



    let kernel32base = get_dll_base_address_from_peb(ppeb as usize,"KERNEL32");
    if kernel32base != 0 {

        let virtualallocaddr = get_dll_raw_export_function(kernel32base,"VirtualAlloc");

        let getprocaddressaddr = get_dll_raw_export_function(kernel32base,"GetProcAddress");

        let loadlibraryaddr = get_dll_raw_export_function(kernel32base,"LoadLibraryA");


        // we are getting the function pointers
        let virtuallocrunner = core::mem::transmute::<usize,
            fn(LPVOID,usize,u32,u32) -> LPVOID
        >(virtualallocaddr);


        let getprocaddressrunner = core::mem::transmute::<usize,
            fn(HMODULE,LPCSTR) -> FARPROC
        >(getprocaddressaddr);


        let loadlibraryrunner = core::mem::transmute::<usize,
            fn(LPCSTR) -> HMODULE
        >(loadlibraryaddr);



        // parsing our old dll contents at ourolddllbase

        if ourolddllbase==0{
            return;
        }

        let dosheader = *((ourolddllbase as *const IMAGE_DOS_HEADER));
        let ntheader = *(((ourolddllbase as usize + dosheader.e_lfanew as usize) as *const IMAGE_NT_HEADERS64));


        // allocating size of our dll using virtualallocrunner
        // TODO: Change memory protections later
        let finaldllbase = virtuallocrunner(core::ptr::null_mut(),ntheader.OptionalHeader.SizeOfImage as usize,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);

        // copying dos header
        //core::ptr::write(finaldllbase as *mut IMAGE_DOS_HEADER, dosheader);


        // copying signature
        //core::ptr::write((finaldllbase as usize + dosheader.e_lfanew as usize) as *mut u32, ntheader.Signature);

        // copying file header
        //core::ptr::write((finaldllbase as usize + dosheader.e_lfanew as usize + 4) as *mut IMAGE_FILE_HEADER, ntheader.FileHeader);


        // copying optional header
        //core::ptr::write((finaldllbase as usize + dosheader.e_lfanew as usize + 4 +
        //                 core::mem::size_of_val(&ntheader.FileHeader)) as *mut IMAGE_OPTIONAL_HEADER64, ntheader.OptionalHeader);



        // copied all the headers
        for i in 0..ntheader.OptionalHeader.SizeOfHeaders{
            *((finaldllbase as usize + i as usize) as *mut u8) =  *((ourolddllbase as usize + i as usize) as *const u8)
        }


        // mapping sections into their respective addresses
        for i in 0..ntheader.FileHeader.NumberOfSections{

            let section = *((ourolddllbase as usize+dosheader.e_lfanew as usize +
            core::mem::size_of::<IMAGE_NT_HEADERS64>()
            + (i as usize * core::mem::size_of::<IMAGE_SECTION_HEADER>())) as *const IMAGE_SECTION_HEADER);


            for j  in 0..*section.Misc.VirtualSize(){

                *((finaldllbase as usize + section.VirtualAddress as usize + j as usize ) as *mut u8) =
                    *((ourolddllbase as usize+section.PointerToRawData as usize + j as usize) as *const u8);

            }



        }



        // fixing imports
        



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
