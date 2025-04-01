
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
use winapi::um::namedpipeapi::*;
use winapi::um::fileapi::*;
use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
use winapi::um::synchapi::WaitForSingleObject;
use crate::tokenmanager::enumeration::TokenInfo;

pub fn createpipe(){

        let pipehandle = unsafe{CreateNamedPipeA(
            "\\\\.\\pipe\\mypipe69\0".as_bytes().as_ptr() as *const i8,
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

            let buffer = lc!("CMD-PRACTICE-FLAG34{GOOD_JOB_ON_RECEIVING_CONFIDENTIAL_INFO_FROM_PIPE}")
                .bytes().collect::<Vec<u8>>();

            let mut byteswritten = 0;
            unsafe{WriteFile(pipehandle,
            buffer.as_ptr() as *const c_void,
            buffer.len() as u32,&mut byteswritten,
            std::ptr::null_mut())};


            unsafe{DisconnectNamedPipe(pipehandle)};

        }



}


pub fn readfrompipe(pipename: &str){

    let mut serverpipename = pipename.bytes().collect::<Vec<u8>>();
    serverpipename.push(0);


    let filehandle = unsafe{CreateFileA(
        serverpipename.as_mut_ptr() as *mut i8,
        GENERIC_READ,
        FILE_SHARE_READ,
        std::ptr::null_mut(),
        3,
        FILE_ATTRIBUTE_NORMAL,
        std::ptr::null_mut()
    )};

    if filehandle==INVALID_HANDLE_VALUE{
        println!("CreateFileA failed: {}",unsafe{GetLastError()});
    }

    if filehandle!=INVALID_HANDLE_VALUE{

        let mut buffer = vec![0u8;1024];
        let mut bytesread = 0;
        unsafe{ReadFile(filehandle,
        buffer.as_mut_ptr() as *mut c_void,
        buffer.len() as u32,&mut bytesread, std::ptr::null_mut())};

        let contents = String::from_utf8_lossy(&buffer);
        println!("{}",contents);

    }


}


pub fn createserverpipeandread(){

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

        let mut buffer = lc!("GIMME_THE_FLAG")
            .bytes().collect::<Vec<u8>>();
        buffer.push(0);

        let mut byteswritten = 0;
        unsafe{WriteFile(pipehandle,
                         buffer.as_ptr() as *const c_void,
                         buffer.len() as u32,&mut byteswritten,
                         std::ptr::null_mut())};


        unsafe{DisconnectNamedPipe(pipehandle)};

    }



}


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

pub fn readfrompipe2(pipename: &str){

    let mut serverpipename = pipename.bytes().collect::<Vec<u8>>();
    serverpipename.push(0);


    let filehandle = unsafe{CreateFileA(
        serverpipename.as_mut_ptr() as *mut i8,
        GENERIC_READ,
        FILE_SHARE_READ,
        std::ptr::null_mut(),
        3,
        FILE_ATTRIBUTE_NORMAL,
        std::ptr::null_mut()
    )};

    if filehandle==INVALID_HANDLE_VALUE{
        println!("CreateFileA failed: {}",unsafe{GetLastError()});
    }

    if filehandle!=INVALID_HANDLE_VALUE{

        let mut buffer = vec![0u8;3];
        let mut bytesread = 0;
        unsafe{ReadFile(filehandle,
                        buffer.as_mut_ptr() as *mut c_void,
                        buffer.len() as u32,&mut bytesread, std::ptr::null_mut())};

        let contents = String::from_utf8_lossy(&buffer).trim_end_matches("\0").to_string();

        if contents=="GIMME_FLAG"{
            println!("{}",lc!("CMD-PRACTICE-FLAG38{NICEJOB_ON_CREATING_SERVERPIPE69_23}"));
        }

    }


}


pub fn createpipeandimpersonate(){


    let mut sa = unsafe{std::mem::zeroed::<SECURITY_ATTRIBUTES>()};

    sa.bInheritHandle = 0;




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

        //let mut buffer = "hi".bytes().collect::<Vec<u8>>();
        //buffer.push(0);

        let mut buffer = vec![0u8;1024];

        let mut byteswritten = 0;
        let res = unsafe{ReadFile(pipehandle,
                         buffer.as_mut_ptr() as *mut c_void,
                         buffer.len() as u32,&mut byteswritten,
                         std::ptr::null_mut())};

        let contents = String::from_utf8_lossy(&buffer);
        println!("received: {}",contents);
        if res==0{
            println!("readfile failed: {}",unsafe{GetLastError()});
        }

        let res = unsafe{ImpersonateNamedPipeClient(pipehandle)};
        if res==0{
            println!("ImpersonateNamedPipeClient failed: {}",unsafe{GetLastError()});
        }

        let tokeninfo = TokenInfo::new(unsafe{GetCurrentProcess()},TOKEN_ALL_ACCESS).unwrap();
        let username = tokeninfo.gettokenuser().unwrap();
        println!("{}",username);

        unsafe{DisconnectNamedPipe(pipehandle)};

    }



}



pub fn writetopipe(pipename: &str,msg: &str){

    let mut serverpipename = pipename.bytes().collect::<Vec<u8>>();
    serverpipename.push(0);


    let filehandle = unsafe{CreateFileA(
        serverpipename.as_mut_ptr() as *mut i8,
        GENERIC_READ|GENERIC_WRITE,
        FILE_SHARE_READ|FILE_SHARE_WRITE,
        std::ptr::null_mut(),
        3,
        FILE_ATTRIBUTE_NORMAL,
        std::ptr::null_mut()
    )};

    if filehandle==INVALID_HANDLE_VALUE{
        println!("CreateFileA failed: {}",unsafe{GetLastError()});
    }

    if filehandle!=INVALID_HANDLE_VALUE{

        let mut buffer = msg.bytes().collect::<Vec<u8>>();
        buffer.push(0);

        //let mut buffer = vec![0u8;1024];

        let mut bytesread = 0;
        unsafe{WriteFile(filehandle,
                        buffer.as_mut_ptr() as *mut c_void,
                        buffer.len() as u32,&mut bytesread, std::ptr::null_mut())};



        unsafe{CloseHandle(filehandle)};
        //unsafe{WaitForSingleObject(GetCurrentProcess(),1000*3)};

    }


}


