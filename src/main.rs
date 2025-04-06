

mod utils;
mod os;
mod processmanager;
mod peparser;
mod tokenmanager;
mod pipemanager;
mod sharemanager;
mod servicemanager;
mod registrymanager;
mod injectionmanager;

use std::io::Read;
use std::net::Shutdown::Write;
use std::thread;
use winapi::um::memoryapi::{ReadProcessMemory, VirtualAlloc, VirtualAllocEx, VirtualProtectEx, WriteProcessMemory};
use winapi::um::processthreadsapi::*;
use winapi::um::winnt::*;
use winapi::um::synchapi::*;
use winapi::ctypes::*;
use utils::parse_structure_from_memory;
use crate::os::getosversion;
use ntapi::ntpsapi::*;
use ntapi::ntmmapi::*;
use crate::peparser::Peparser64;
use crate::processmanager::enumeration::{get_process_info_by_name, get_processes, get_processes_from_createtoolhelp32snapshot, processchecker, processcheckerwithargs, readunicodestringfrommemory};
use crate::utils::{getclipboard, setclipboard, ReadStringFromMemory};
use winapi::um::winnt::*;
use winapi::shared::minwindef::*;
use winapi::um::libloaderapi::*;
use ntapi::ntpebteb::*;
use winapi::shared::ntdef::{NTSTATUS, NT_SUCCESS, NULL, OBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::CloseHandle;
use winapi::um::winuser::*;
use winapi::um::synchapi::*;
use crate::pipemanager::pipes::*;
use winapi::um::securitybaseapi::*;

use winapi::um::winnt::*;
use winapi::ctypes::*;
use winapi::shared::minwindef::DWORD;
use winapi::um::errhandlingapi::*;
use winapi::um::handleapi::*;
use winapi::um::memoryapi::*;
use winapi::um::processthreadsapi::*;
use winapi::um::securitybaseapi::*;
use winapi::um::winbase::*;
use winapi::um::processthreadsapi::*;
use winapi::um::heapapi::*;

#[macro_use]
extern crate litcrypt;

use md5;
use winapi::um::fileapi::{CreateFileA, DeleteFileA, ReadFile, WriteFile, OPEN_ALWAYS, OPEN_EXISTING};
use winapi::um::minwinbase::{OVERLAPPED, SECURITY_ATTRIBUTES};
use crate::tokenmanager::enumeration::*;
use crate::tokenmanager::sids::allocatesid;
use crate::tokenmanager::tokens::runme37;

use_litcrypt!();



use base64::*;
use ntapi::ntapi_base::{CLIENT_ID, PCLIENT_ID};
use ntapi::ntobapi::NtClose;
use winapi::um::ktmw32::*;
use winapi::um::namedpipeapi::{*, CreatePipe};

#[no_mangle]
#[link_section = "text"]
static mut stub:[u8;23] = [0;23];



pub fn createpipe2(){

    let pipehandle = unsafe{CreateNamedPipeA(
        "\\\\.\\pipe\\myserverpipe69\0".as_bytes().as_ptr() as *const i8,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE,
        1,
        1024,
        1024,
        0,
        std::ptr::null_mut()
    )};

    if pipehandle==INVALID_HANDLE_VALUE{
        println!("CreateNamedPipeA failed: {}",unsafe{GetLastError()});
    }

    if pipehandle!=INVALID_HANDLE_VALUE{

        let res =  unsafe{ConnectNamedPipe(pipehandle,std::ptr::null_mut())};

        let buffer = "GIMME_FLAG"
            .bytes().collect::<Vec<u8>>();

        let mut byteswritten = 0;
        unsafe{WriteFile(pipehandle,
                         buffer.as_ptr() as *const c_void,
                         buffer.len() as u32,&mut byteswritten,
                         std::ptr::null_mut())};


        unsafe{DisconnectNamedPipe(pipehandle)};

    }



}


fn main() {
    /*let args = std::env::args().collect::<Vec<String>>();

    // args[1] = filenametoexecute.exe

    if args.len()!=2{
        println!("Please supply the filename to execute") ;
        std::process::exit(0);
    }

    let res = Peparser64::parse_from_file(&args[1]);
    if res.is_err(){
        println!("{}",res.err().unwrap());
        std::process::exit(0);
    }

    let dlls:[&str;0] = [];
    let mut dllspresent: Vec<bool> = vec![false;dlls.len()];
    let functionnames:[&str;4]  = ["waitfordebugevent","continuedebugevent",
    "getthreadcontext","setthreadcontext"];
    let blacklist:[&str;0] = [];
    let mut blacklistpresent: Vec<bool> = vec![false;blacklist.len()];

    let mut functionspresent: Vec<bool> = vec![false;functionnames.len()];
    let peparser = res.unwrap();
    let imports = peparser.get_imports();

    // checking dlls
    for i in 0..dlls.len(){
        for j in 0..imports.len(){
            if imports[j].dllname.to_lowercase() == dlls[i].to_lowercase(){
                dllspresent[i] = true;
            }
        }
    }

    for i in 0..dllspresent.len(){
        if dllspresent[i]==false{
            println!("Please use the {}",dlls[i]);
            std::process::exit(0);
        }
    }


    // checking functions
    for i in 0..functionnames.len(){
        for j in 0..imports.len(){
            for (funcname,thunk) in imports[j].functions.iter(){
                if funcname.to_lowercase() == functionnames[i].to_lowercase(){
                    functionspresent[i]=true;
                }
            }
        }
    }
    for i in 0..functionspresent.len(){
        if functionspresent[i]==false{
            println!("Please use the {}",functionnames[i]);
            std::process::exit(0);
        }
    }


    // checking blacklist functions
    for i in 0..blacklist.len(){
        for j in 0..imports.len(){
            for (funcname,addr) in imports[j].functions.iter(){
                if funcname.to_lowercase()==blacklist[i].to_lowercase(){
                    println!("Please don't use {}",blacklist[i]);
                    std::process::exit(0);
                }
            }
        }
    }


    println!("good to go");
    std::process::exit(0);*/

    //let result = os::runfile(&args[1]);


    // createprocess with arguments

    // arg[1] = filename to execute
    // arg[2] = argument

    let p = get_processes();
    let mut isdllpresent = false;
    let mut isprocesspresent = false;

    for i in 0..p.len(){

        if p[i].get_process_name().to_lowercase()=="examprocess4.exe"{

            isprocesspresent = true;
            let dlls = p[i].get_loaded_dlls_basedllname().unwrap();


            for (dllname,dllbase) in dlls.iter(){

                if dllname.to_lowercase()=="test.dll"{
                    isdllpresent=true;
                    break;
                }

            }



        }

    }

    if isdllpresent==false && isprocesspresent==true{
        println!("{}",lc!("EXAM-FLAG4{FANTASTICALLY_HID_THE_IN_LOAD_ORDER_MODULELIST}"));
        std::process::exit(0);
    }

    println!("Sorry, Try Again");

}