# Patrick Sacchet
# INFA 732
# Lab 4 (extra credit)

# Main file for interfacing with the user and parsing PE files 

from PE_DataStructs import *

#########################################################
# Validate our MZ signature in our DOS header
    # Params:
        # dos_header - DOSHeader struct 
    # return:
        # bool - True for success, False otherwise
#########################################################
def ValidateSignature(dos_header : DOSHeader) -> bool:
    try:

        if (dos_header.magic == DOS_MAGIC_VALUE):
            print("MZ signature present!")
            return True

        else:
            return False

    except Exception as e:
        print("Failed to validate signature: " + str(e))
        return False

#########################################################
# Print our DOS Stub message
    # Params:
        # dos_stub - DOSStub struct 
    # return:
        # bool - True for success, False otherwise
#########################################################
def PrintDosMessage(dos_stub : DOSStub, ) -> bool:
    try:
        dos_bytes = bytearray(dos_stub.stub)
        print(dos_bytes[DOS_STUB_MSG_OFFSET:].decode()) # The message seems to start at offset 0xE
        return True

    except Exception as e:
        print("Failed to print dos message: " + str(e))
        return False

#########################################################
# Print the ImageBase address
    # Params:
        # nt_headers - ImageNTHeaders struct
    # return:
        # bool - True for success, False otherwise
#########################################################        
def PrintImageBaseAddress(nt_headers : ImageNTHeaders) -> bool:
    try:
        print(hex(nt_headers.contents.optional_header.image_base))
        return True

    except Exception as e:
        print("Failed to print image base address: " + str(e))
        return False

#########################################################
# Return true if DLL, false otherwise
    # Params:
        # nt_headers - ImageNTHeaders struct
    # return:
        # bool - True for success, False otherwise
#########################################################
def DetermineDll(nt_headers : ImageNTHeaders) -> bool:
    try:
        if (nt_headers.contents.file_header.characteristics & IMAGE_FILE_DLL):
            print("Binary is a DLL!")
            return True
        elif (nt_headers.contents.file_header.characteristics & IMAGE_FILE_EXECUTABLE_IMAGE):
            print("Binary is a executable!")
            return False
        else:
            print("Cannot determine binary type :(")
            return False
    
    except Exception as e:
        print("Failed to determine whether binary is DLL: " + str(e))
        return False

#########################################################
# Print all exports if binary is a DLL
    # Params:
        # nt_headers - ImageNTHeaders struct
        # export_dir - ImageExportDirectory struct
        # raw_pe_bytes - byte array of all bytes read from PE file (useful for reading past what we already know via our struct casts)
        # section_align - our section align offset to convert addresses for our exports
    # return:
        # bool - True for success, False otherwise
#########################################################
def PrintExports(nt_headers : ImageNTHeaders, exportDir : ImageExportDirectory, raw_pe_bytes : bytes, section_align : int) -> bool:
    try:
        if (nt_headers.contents.optional_header.magic & PE_PLUS_MAGIC_VALUE and not nt_headers.contents.file_header.characteristics & IMAGE_FILE_32_BIT_MACHINE):
            print("Binary is 64-bit!")
            
            actual_name_addr = exportDir.contents.name - section_align
            print("Address of our name: " + hex(actual_name_addr)) 

            name = c_char_p(raw_pe_bytes[actual_name_addr:])
            print("Name of our export dir: " + name.value.decode())
            
            name_addr = exportDir.contents.addr_of_names - section_align
            print("Address of our names " + hex(name_addr)) 

            print("There are " + str(int(exportDir.contents.num_of_names)) + " exports: ")
                    
            num_exports = exportDir.contents.num_of_names
            index = 0
            while(index < num_exports):
                entry = raw_pe_bytes[name_addr+(4*index):name_addr+((index+1)*4)]
                entry_offset = int.from_bytes(entry, "little") - section_align
                export = c_char_p(raw_pe_bytes[entry_offset:]).value.decode()
                print("\t" + export)
        
                index+=1

            return True
        
        elif (nt_headers.contents.optional_header.magic & PE_MAGIC_VALUE):
            print("Binary is 32-bit -> not yet supported :(")
            return False
        
        else:
            print("Identified machine type in magic bytes: " + str(hex(nt_headers.contents.optional_header.magic)))
            return False

    except Exception as e:
        print("Failed to print exports: " + str(e))
        return False

#########################################################
# Print all our sections
    # Params:
        # section_bytes - byte array containing those bytes relevant to our sections
        # num_sections - the number of sections we have
    # return:
        # bool - True for success, False otherwise
#########################################################
def PrintSections(section_bytes : bytes, num_sections : int) -> bool:
    try:
        index = 0

        while (index < num_sections):
            section = cast(section_bytes[index*sizeof(ImageSectionHeader):(index+1)*sizeof(ImageSectionHeader)], POINTER(ImageSectionHeader))
            name = bytearray(section.contents.name)
            print(name[0:].decode())
            index += 1

        return True

    except Exception as e:
        print("Failed to print sections: " + str(e))

#########################################################
# Main program entry 
    # Will take a filepath from the user to a binary and attempt to print PE information 
#########################################################
def main():
    # Take and read file from user
    file_path = input("Please enter path to the file > ")

    try:
        open_file = open(file_path, "r+b") # read and write binary
        file_bytes = open_file.read()

    except IOError as e:
        print ("Cannot open file! Exiting...")
        return
    
    except Exception as e:
        print ("Unexpected exception when openening file: " + str(e))
        return
    
    finally:
        open_file.close()

    print("================================================")

    pe_header = cast(file_bytes, POINTER(PEHeader))

    # PE Header address start:  0xf8
    pe_address = pe_header.contents.dos_header.lfanew
    
    # Detect MZ signature
    print("Detecting MZ signature...")

    dos_header = pe_header.contents.dos_header
    
    if (not ValidateSignature(dos_header)):
        print("Failed signature check; returning...")
        return

    print("================================================")
    
    # Print the DOS stub message
    print("Printing DOS stub message: ")
    #dos_message = cast(file_bytes[64:128], POINTER(DOSStub))
    dos_stub = pe_header.contents.dos_stub
    if (not PrintDosMessage(dos_stub)):
        print("Failed to print DOS stub message :(; returning...")
        return

    print("================================================")
    
    # Print the ImageBase address
    print("PE Header address start: ", hex(pe_address))
    print("Obtaining ImageBase address: ")

    nt_headers = cast(file_bytes[pe_address:pe_address+sizeof(ImageNTHeaders)], POINTER(ImageNTHeaders))
    if (not PrintImageBaseAddress(nt_headers)):
        print("Failed to grab ImageBase address; returning...")
        return

    print("================================================")
    
    # Export dir is the first data directory so use that as the offset
    section_align = nt_headers.contents.optional_header.section_alignment
    export_dir_addr = nt_headers.contents.optional_header.data_directory[0].virtual_address 
    actual_dir_addr = export_dir_addr - section_align
    export_dir_size = nt_headers.contents.optional_header.data_directory[0].size
    print("Virtual address of our export dir is " + hex(export_dir_addr))
    print("Relative virtual address of our export dir is " + hex(actual_dir_addr))
    print("Size of our export dir is " + hex(export_dir_size))
    
    export_dir = cast(file_bytes[actual_dir_addr:actual_dir_addr+export_dir_size], POINTER(ImageExportDirectory))

    # Print whether the executable is a DLL or not
    print("Determining whether this binary is a executable or a DLL...")
        # IMAGE_FILE_HEADER -> characteristics 
    if (DetermineDll(nt_headers)):
        # If it is a DLL, print any exported functions
        if (not PrintExports(nt_headers, export_dir, file_bytes, section_align)):
            print ("Failed to print exports!")
            return 

    print("================================================")

    # Print all sections 
    num_sections = nt_headers.contents.file_header.num_sections

    print("There are " + str(num_sections) + " sections:")

    # Our sections will begin at the end of where our NT headers are; cast this to use and print the names
    section_bytes = file_bytes[pe_address+sizeof(ImageNTHeaders):pe_address+sizeof(ImageNTHeaders)+(sizeof(ImageSectionHeader)*num_sections)]

    if (not PrintSections(section_bytes, num_sections)):
        print("Failed to print sections!")
        return

    return


if __name__ == '__main__':
    main()