# Patrick Sacchet

# My own implementations of native Windows structs using ctypes for easy casting and field manipulation

from ctypes import *

# Offsets
DOS_MAGIC_VALUE = 0x5A4D
DOS_STUB_MSG_OFFSET = 0xE

# Characteristics to determine whether DLL or executable 
IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
IMAGE_FILE_DLL = 0x2000

# Offsets into the data directory of our PE header
EXPORT_TABLE_PE = 0x60
EXPORT_TABLE_PE_PLUS = 0x70

# Characteristics for 32 vs 64 bit
IMAGE_FILE_32_BIT_MACHINE = 0x100

# Magic values that determine whether we have PE or PE+
PE_MAGIC_VALUE = 0x20b
PE_PLUS_MAGIC_VALUE = 0x10b

# Directory information
IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 0x10

# Section info
IMAGE_SIZEOF_SHORT_NAME = 0x8

'''
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
  } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
'''
class DOSHeader(Structure):
    _fields_= [
        ("magic", c_short),
        ("cblp", c_short),
        ("cp", c_short),
        ("crlc", c_short),
        ("cparhdr", c_short),
        ("minalloc", c_short),
        ("maxalloc", c_short),
        ("ss", c_short),
        ("sp", c_short),
        ("csum", c_short),
        ("ip", c_short),
        ("cs", c_short),
        ("lfarlc", c_short),
        ("ovno", c_short),
        ("res", c_short*4),
        ("oemid", c_short),
        ("oeminfo", c_short),
        ("res2", c_short*10),
        ("lfanew", c_ulong) # address where PE header begins 
    ]

# DOS Stub
    # Technically dynamically generated so just use this to print our DOS message for now
class DOSStub(Structure):
    _fields_ = [
        ("stub", c_byte*64)
    ]

'''
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
'''
class ImageDataDirectory(Structure):
    _fields_ = [
        ("virtual_address", c_ulong),
        ("size", c_ulong)
    ]

'''
typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
'''
class ImageFileHeader(Structure):
    _fields_ = [
        ("machine", c_short),
        ("num_sections", c_short),
        ("time_date_stamp", c_ulong),
        ("symbol_table", c_ulong),
        ("num_symbols", c_ulong),
        ("opt_header_size", c_short),
        ("characteristics", c_short)
    ]

'''
typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    ULONGLONG   ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD        MajorOperatingSystemVersion;
    WORD        MinorOperatingSystemVersion;
    WORD        MajorImageVersion;
    WORD        MinorImageVersion;
    WORD        MajorSubsystemVersion;
    WORD        MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    WORD        Subsystem;
    WORD        DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;
'''
class ImageOptionalHeader(Structure):
    _fields_ = [
        ("magic", c_ushort),
        ("maj_link_version", c_byte),
        ("min_link_version", c_byte),
        ("size_of_code", c_ulong),
        ("size_of_init_data", c_ulong),
        ("size_of_uninit_data", c_ulong),
        ("add_entry_point", c_ulong),
        ("base_of_code", c_ulong),
        ("image_base", c_ulonglong),
        ("section_alignment", c_ulong),
        ("file_alignment", c_ulong),
        ("maj_op_sys_ver", c_short),
        ("min_op_sys_ver", c_short),
        ("maj_image_ver", c_ushort),
        ("min_image_ver", c_ushort),
        ("maj_sub_ver", c_ushort),
        ("min_sub_ver", c_ushort),
        ("win32_ver_val", c_ulong),
        ("size_of_image", c_ulong),
        ("size_of_headers", c_ulong),
        ("check_sum", c_ulong),
        ("subsystem", c_ushort),
        ("dll_characteristics", c_ushort),
        ("size_of_stack_res", c_ulonglong),
        ("size_of_stack_com", c_ulonglong),
        ("size_of_heap_res", c_ulonglong),
        ("size_of_heap_com", c_ulonglong),
        ("loader_flags", c_ulong),
        ("num_of_rva_and_sizes", c_ulong),
        ("data_directory", ImageDataDirectory*IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
    ]

'''
typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;
'''
class ImageNTHeaders(Structure):
    _fields_ = [
        ("signature", c_ulong),
        ("file_header", ImageFileHeader),
        ("optional_header", ImageOptionalHeader)
    ]

# PE Header
    # Our own combination of DOS/NT fields
class PEHeader(Structure):
    _fields_ = [
        ("dos_header", DOSHeader),
        ("dos_stub", DOSStub),
        ("nt_headers", ImageNTHeaders)
    ]

'''
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;     // RVA from base of image
    DWORD   AddressOfNames;         // RVA from base of image
    DWORD   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

'''
class ImageExportDirectory(Structure):
    _fields_ = [
        ("characteristics", c_ulong),
        ("time_date_stamp", c_ulong),
        ("maj_version", c_ushort),
        ("min_version", c_ushort),
        ("name", c_ulong), # relative to image base?
        ("base", c_ulong),
        ("num_of_functions", c_ulong),
        ("num_of_names", c_ulong),
        ("addr_of_funcs", c_ulong), # RVA
        ("addr_of_names", c_ulong), # RVA
        ("addr_of_name_ords", c_ulong) # RVA
    ]

# Union within our ImageSectionHeader
    # MUST be declared as a union or our byte offset is wrong!
class Misc(Union):
    _fields_ = [
        ("physical_address", c_ulong),
        ("virtual_address", c_ulong)
    ]

'''
typedef struct _IMAGE_SECTION_HEADER {
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
            DWORD   PhysicalAddress;
            DWORD   VirtualSize;
    } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
'''
class ImageSectionHeader(Structure):
    _fields_ = [
           ("name", c_byte*IMAGE_SIZEOF_SHORT_NAME),
           ("misc", Misc),
           ("virtual_address", c_ulong),
           ("size_of_raw_data", c_ulong),
           ("pointer_to_raw_data", c_ulong),
           ("pointer_to_relocations", c_ulong),
           ("pointer_to_line_numbers", c_ulong),
           ("num_of_relocations", c_ushort),
           ("num_of_line_numbers", c_ushort),
           ("characteristics", c_ulong)
    ]

