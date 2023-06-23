
use bindings::Windows::Win32::System::Threading::GetCurrentProcess;
use std::{io, process};
use data::{PVOID, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, MEM_COMMIT, MEM_RESERVE, ustring,DWORD};
use std::ffi::CString;
use std::io::{Read};

fn pause(){
    let mut user_input = String::new();
        let stdin = io::stdin(); // We get `Stdin` here.
        stdin.read_line(&mut user_input);
}

fn main() {
    unsafe{
        let intro_text = "\n
        ████████╗██╗░░██╗██╗░██████╗  ██╗░██████╗  ░░░░░██╗██╗░░░██╗░██████╗████████╗  ░█████╗░
        ╚══██╔══╝██║░░██║██║██╔════╝  ██║██╔════╝  ░░░░░██║██║░░░██║██╔════╝╚══██╔══╝  ██╔══██╗
        ░░░██║░░░███████║██║╚█████╗░  ██║╚█████╗░  ░░░░░██║██║░░░██║╚█████╗░░░░██║░░░  ███████║ 
        ░░░██║░░░██╔══██║██║░╚═══██╗  ██║░╚═══██╗  ██╗░░██║██║░░░██║░╚═══██╗░░░██║░░░  ██╔══██║
        ░░░██║░░░██║░░██║██║██████╔╝  ██║██████╔╝  ╚█████╔╝╚██████╔╝██████╔╝░░░██║░░░  ██║░░██║
        ░░░╚═╝░░░╚═╝░░╚═╝╚═╝╚═════╝░  ╚═╝╚═════╝░  ░╚════╝░░╚═════╝░╚═════╝░░░░╚═╝░░░  ╚═╝░░╚═╝
        
        ██████╗░░█████╗░░█████╗░
        ██╔══██╗██╔══██╗██╔══██╗
        ██████╔╝██║░░██║██║░░╚═╝
        ██╔═══╝░██║░░██║██║░░██╗
        ██║░░░░░╚█████╔╝╚█████╔╝
        ╚═╝░░░░░░╚════╝░░╚════╝░ \n";
        println!("{intro_text}");


        //
        //
        // Allocate Memory for the Shellcode
        //
        //
        let addr = 0 as isize; // for base address of allocated shellcode
        let addr: PVOID = std::mem::transmute(addr); // making it a PVOID
        let base_address_shellcode: *mut PVOID = std::mem::transmute(&addr); //making it a *BaseAddress
        let zero_bits = 0 as usize; //NtAllocateMemory Zero Bits
        let shellcode: [u8; 5] =  [0x48,0x65,0x6c,0x6c,0x6f]; // Shellcode Here
        //let decoded_sh: [u8; 5] =  [0x02,0x6f,0x51,0x54,0xb5];
        let size_sh = shellcode.len();// len of shellcode
        let size: *mut usize = std::mem::transmute(&size_sh); //pointer to size
        let ret = dinvoke::nt_allocate_virtual_memory(GetCurrentProcess(), base_address_shellcode, zero_bits, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); //call ntAllocateMemory for allocating RWX memory 
        if ret != 0
        {
            println!("{}",("[x] Memory allocation failed."));
            return;
        }


        println!("[+] Memory successfully allocated at addr:  {addr:#?}");
        println!("[+] Press Enter to continue...");
        pause();
        //
        //
        // Write Shellcode to the Allocated Memory
        //
        //
        println!("[+] Writing Shellcode to Memory.");
        let buffer: PVOID = std::mem::transmute(shellcode.as_ptr()); // Getting pointer to Shellcode
        let dwsize = shellcode.len(); //calulating its length
        let written: usize = 0;//bytes written to memory
        let bytes_written: *mut usize = std::mem::transmute(&written);//pointer to bytes written
        let ret = dinvoke::nt_write_virtual_memory(GetCurrentProcess(), addr, buffer, dwsize, bytes_written); // Writing to memory
        println!("[+] Shellcode was successfully written to memory at {addr:#?}");
        println!("[+] Press Enter to continue...");
        pause();
        //
        //
        // Make appropriate ustring structures for key and shellcode
        // Note that buffer to shellcode is pointing to memory location to make sure and identify that changes are directly made into memory
        //
        //
        let key: [u8; 14] = *b"alphaBetagamma"; //encryption key
        let key_len = key.len()  as u32; // just the size
        let key_buffer: PVOID = std::mem::transmute(key.as_ptr()); //get pointer to key
        let key_ustring = ustring {length: key_len, maximumlength: key_len, buffer: key_buffer,}; // Create the ustring variable for key
        let mut buffer_ustring = ustring {length: size_sh as u32, maximumlength: size_sh as u32, buffer: addr,}; //create ustring for the data to encrypt. Note applies here. The buffer is pointing to the memeory location for encryption
        //
        //
        // Calling SystemFunction032 for memeory encryption
        //
        //
        println!("[+] Applying SystemFunction032 at address {addr:#?} for Encryption. ");
        dinvoke::system_function_032(&mut buffer_ustring, &key_ustring);
        println!("[+] Press Enter to continue...");
        pause();
        //
        //
        // Calling SystemFunction032 for memeory decryption
        //
        //
        println!("[+] Applying SystemFunction032 at address {addr:#?} for Decryption. ");
        dinvoke::system_function_032(&mut buffer_ustring, &key_ustring);
        println!("[+] Press Enter to continue...");
        pause();
    }
} 