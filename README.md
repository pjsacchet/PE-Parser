# PE-Parser

## Description
Custom parsing files for Portable Executable (PE) headers, available currently only for x86/32-bit binaries. This project comprises of the main parser (PE_Parser.py) which utilizes those structs outlined in PE_Data_Structs.py to map and parse common sections of a portable executable file. Output includes:
- Detecting the MZ signature
- Printing the DOS stub message
- Printing the ImageBase address
- Printing whether the binary is a DLL or not
  - If it is a DLL, print exported functions
- Printing all sections

## Usage
```
python3 PE_Parser.py
```

## Example Output
### Single export:
```
Please enter path to the file > ...\Binaries\RAT-Dll-single-export.dll
================================================
Detecting MZ signature...
MZ signature present!
================================================
Printing DOS stub message:
This program cannot be run in DOS mode.
$
================================================
PE Header address start:  0xf8
Obtaining ImageBase address:
0x180000000
================================================
Virtual address of our export dir is 0x91d0
Relative virtual address of our export dir is 0x81d0
Size of our export dir is 0x4c
Determining whether this binary is a executable or a DLL...
Binary is a DLL!
Binary is 64-bit!
Address of our name: 0x8202
Name of our export dir: RAT-Dll.dll
Address of our names 0x81fc
There are 1 exports:
        startListen
================================================
There are 6 sections:
.text
.rdata
.data
.pdata
.rsrc
.reloc
```
### Multiple exports:
```
Please enter path to the file > ...\Binaries\RAT-Dll-three-exports.dll
================================================
Detecting MZ signature...
MZ signature present!
================================================
Printing DOS stub message:
This program cannot be run in DOS mode.
$
================================================
PE Header address start:  0xf8
Obtaining ImageBase address:
0x180000000
================================================
Virtual address of our export dir is 0x9250
Relative virtual address of our export dir is 0x8250
Size of our export dir is 0x78
Determining whether this binary is a executable or a DLL...
Binary is a DLL!
Binary is 64-bit!
Address of our name: 0x8296
Name of our export dir: RAT-Dll.dll
Address of our names 0x8284
There are 3 exports:
        sendFailure
        sendSuccess
        startListen
================================================
There are 6 sections:
.text
.rdata
.data
.pdata
.rsrc
.reloc
```
### Other file types:
```
Please enter path to the file > ...\Binaries\RAT-Exe.exe
================================================
Detecting MZ signature...
MZ signature present!
================================================
Printing DOS stub message:
This program cannot be run in DOS mode.
$
================================================
PE Header address start:  0xf8
Obtaining ImageBase address:
0x140000000
================================================
Virtual address of our export dir is 0x0
Relative virtual address of our export dir is -0x1000
Size of our export dir is 0x0
Determining whether this binary is a executable or a DLL...
Binary is a executable!
================================================
There are 6 sections:
.text
.rdata
.data
.pdata
.rsrc
.reloc
```
## TODO:
- Support x64 binaries 
- Print other pieces of potentially interesting information 