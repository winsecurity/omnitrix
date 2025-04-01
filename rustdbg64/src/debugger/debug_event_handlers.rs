use std::collections::HashMap;
use winapi::ctypes::c_void;
use winapi::um::minwinbase::*;
use winapi::um::processthreadsapi::*;
use winapi::um::winnt::IMAGE_EXPORT_DIRECTORY;
use crate::peparser;
use crate::utils::{parse_structure_from_memory, ReadStringFromMemory};

pub fn create_process_event_handler(debugevent: &DEBUG_EVENT){
    //println!("[+] Debug event {} has occurred inside process {}",
    //         debugevent.dwDebugEventCode,debugevent.dwProcessId);


    if debugevent.dwDebugEventCode == 3{
        println!("CREATE_PROCESS_EVENT has occurred");


        //let createprocessdebuginfo = parse_structure_from_memory::<CREATE_PROCESS_DEBUG_INFO>(unsafe{GetCurrentProcess()},
        //                           (debugevent  as *const _ as usize +12) as usize).unwrap();


        let imagename = crate::utils::ReadStringFromMemory(unsafe{GetCurrentProcess()},
                                                           unsafe{debugevent.u.CreateProcessInfo().lpImageName});

        println!("Image name: {}",imagename);
        println!("process base: {:x?}",unsafe{debugevent.u.CreateProcessInfo().lpBaseOfImage});



    }


}

pub fn exception_event_handler(debugevent: &DEBUG_EVENT,softwarebreakpoints: HashMap<usize,u8> ){


    if debugevent.dwDebugEventCode == 1{
        println!("[+] EXCEPTION Debug event {} has occurred inside thread {}",
                 debugevent.dwDebugEventCode,debugevent.dwThreadId);

        let exceptioncode = unsafe{debugevent.u.Exception().ExceptionRecord.ExceptionCode};
        let exceptionaddress = unsafe{debugevent.u.Exception().ExceptionRecord.ExceptionAddress};
        println!("Exception code: {}",unsafe{debugevent.u.Exception().ExceptionRecord.ExceptionCode});

        match exceptioncode{
            EXCEPTION_ACCESS_VIOLATION => {println!("EXCEPTION_ACCESS_VIOLATION");},
            EXCEPTION_BREAKPOINT => {

                println!("EXCEPTION_BREAKPOINT");

                for (address,value) in softwarebreakpoints.iter(){

                    if *address == exceptionaddress as usize{

                        // we need to restore the breakpoint



                    }

                }



            },
            EXCEPTION_FLT_DIVIDE_BY_ZERO => {println!("EXCEPTION_FLT_DIVIDE_BY_ZERO");},
            _ => {}
        }

        println!("Exception address: {:x?}",unsafe{debugevent.u.Exception().ExceptionRecord.ExceptionAddress});




    }


}

pub fn load_dll_event_handler(debugevent: &DEBUG_EVENT,pi:PROCESS_INFORMATION){

    if debugevent.dwDebugEventCode == 6{
        println!("LOAD_DLL_DEBUG_EVENT has occurred inside thread: {}",debugevent.dwThreadId);


        //let dllname = ReadStringFromMemory( unsafe{GetCurrentProcess()},unsafe{debugevent.u.LoadDll().lpImageName});

        let dllbase = unsafe{debugevent.u.LoadDll().lpBaseOfDll};
        println!("DLL Base: {:x?}",unsafe{debugevent.u.LoadDll().lpBaseOfDll});
        //let pe = peparser::Peparser64::parse_from_memory(debugevent.dwProcessId,dllbase as usize).unwrap();

        /*let ntheader = pe.get_ntheader().unwrap();

        if ntheader.OptionalHeader.DataDirectory[0].Size !=0{

            let exports = parse_structure_from_memory::<IMAGE_EXPORT_DIRECTORY>(pi.hProcess,(dllbase as usize+ ntheader.OptionalHeader.DataDirectory[0].VirtualAddress as usize)).unwrap();

            let dllname = ReadStringFromMemory(pi.hProcess,(dllbase as usize + exports.Name as usize) as *const c_void);

            println!("DLL name: {}",dllname);

            if dllname.to_lowercase()=="ntdll.dll"{
                println!("-----------------------------------------------------------------------");

                println!("DLL name: {}",dllname);

                println!("-----------------------------------------------------------------------");


            }
        }

*/
        //println!("DLL name: {}",dllname);
        //println!("DLL Image name pointer: {:x?}",unsafe{debugevent.u.LoadDll().lpImageName});

        println!();
    }

}

