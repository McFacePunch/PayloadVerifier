import lief
import sys
import os
import string
import re
from datetime import datetime

def check_debug_sections(binary):
    debug_sections = [
        ".debug", ".pdb", ".dwarf", ".stab", ".symtab", ".strtab", ".note",
        ".comment", ".GCC.command.line", ".jcr", ".note.gnu.build-id", ".note.ABI-tag"
    ]
    found_debug_sections = []
    for section in binary.sections:
        if any(debug in section.name.lower() for debug in debug_sections):
            found_debug_sections.append(section.name)
    return found_debug_sections

def check_debug_symbols(binary):
    debug_symbol_keywords = [
        "debug", "pdb", "dwarf", "source", "filename", ".cpp", ".c", ".cc", ".h",
        "llvm", "gcc", "clang", "mingw", "msvc", "__DATE__", "__TIME__", "main"
    ]
    found_debug_symbols = []
    for symbol in binary.symbols:
        if any(keyword in symbol.name.lower() for keyword in debug_symbol_keywords):
            found_debug_symbols.append(symbol.name)
    return found_debug_symbols

def check_pdb_path(binary):
    # Ensure the binary is a PE format binary
    if isinstance(binary, lief.PE.Binary) and binary.has_debug:
        try:
            # Access the debug entry
            debug_entry = binary.debug[0]
            
            # Check if the debug entry is of type CodeView and has a filename
            if isinstance(debug_entry, lief.PE.CodeViewPDB):
                pdb_path = debug_entry.filename
                if pdb_path:
                    return pdb_path
        except (IndexError, AttributeError) as e:
            # Safely handle cases where debug info or the pdb path is missing
            print(f"Warning: PDB path not found or debug entry missing. Error: {e}")
    return None

# Strings from PEs in a static analysis way is annoying so this is like strings cli but python
def check_suspicious_strings(file_path):
    suspicious_keywords = [
        ".cpp", ".c", ".h", "source", "debug", "pdb", "llvm", "gcc", "clang",
        "mingw", "msvc", "__DATE__", "__TIME__", "/tmp/", "/var/", "C:\\", "\\\\", "/Users/"
    ]
    found_suspicious_strings = []

    # Open the binary file and extract printable strings
    with open(file_path, "rb") as f:
        binary_data = f.read()

        # Extract strings of printable characters
        printable_strings = ''.join([chr(b) if chr(b) in string.printable else '\n' for b in binary_data]).split('\n')

        # Search for suspicious keywords in extracted strings
        for s in printable_strings:
            if any(keyword in s.lower() for keyword in suspicious_keywords):
                found_suspicious_strings.append(s)

    return found_suspicious_strings

def check_stripped_binary(binary):
    return len(binary.symbols) == 0

def check_timestamps(binary):
    timestamps = []
    if isinstance(binary, lief.PE.Binary):
        pe_timestamp = binary.header.time_date_stamps
        if pe_timestamp:
            dt = datetime.utcfromtimestamp(pe_timestamp)
            timestamps.append(f"PE Timestamp: {dt} UTC")
    elif isinstance(binary, lief.ELF.Binary):
        build_id = binary.get(lief.ELF.DYNAMIC_TAGS.GNU_BUILD_ID)
        if build_id:
            timestamps.append(f"ELF Build ID: {build_id.hash.hex()}")
    elif isinstance(binary, lief.MachO.Binary):
        for command in binary.commands:
            if isinstance(command, lief.MachO.DylinkerCommand):
                pass  # Usually does not contain timestamps
            elif isinstance(command, lief.MachO.SourceVersion):
                timestamps.append(f"Mach-O Source Version: {command.version}")
            elif isinstance(command, lief.MachO.BuildVersion):
                timestamps.append(f"Mach-O Build Version: Platform {command.platform}, Min OS {command.minos}, SDK {command.sdk}")
    return timestamps

def check_platform_specific(binary):
    if lief.MachO in binary.format:
        # macOS-specific checks
        if binary.has_function_starts:
            print("macOS function start information found.")
        if binary.has_dyld_info:
            print("DYLD information found.")
    elif lief.PE in binary.format:
        # Windows-specific checks
        pdb_path = check_pdb_path(binary)
        if pdb_path:
            print(f"PDB path found: {pdb_path}")
        else:
            print("No PDB path found.")
    elif lief.ELF in binary.format:
        # Linux-specific checks
        if binary.has_dynamic_entries:
            print("Dynamic entries found.")
        if binary.has_note_section:
            print("ELF Note section found.")

def check_compiler_metadata(file_path):
    compiler_patterns = [
        r"GCC:\s*\(.*\)", r"clang version\s*[^\s]+", r"MSVC\s*[\d\.]+", r"MinGW", r"Apple LLVM version\s*[^\s]+"
    ]
    found_compiler_info = []

    # Open the binary file and extract printable strings
    with open(file_path, "rb") as f:
        binary_data = f.read()

        # Extract strings of printable characters
        printable_strings = ''.join([chr(b) if chr(b) in string.printable else '\n' for b in binary_data]).split('\n')

        # Search for compiler patterns in extracted strings
        for s in printable_strings:
            for pattern in compiler_patterns:
                matches = re.findall(pattern, s)
                if matches:
                    found_compiler_info.extend(matches)

    return found_compiler_info

def check_version_info(binary):
    version_info = []

    # Check if the binary has resources
    if isinstance(binary, lief.PE.Binary) and binary.has_resources:
        try:
            # Check if the resources contain version information
            vs_version_info = binary.resources.version
            if vs_version_info:
                version_info.append(f"Product Name: {vs_version_info.string_file_info.product_name}")
                version_info.append(f"Company Name: {vs_version_info.string_file_info.company_name}")
                version_info.append(f"File Version: {vs_version_info.string_file_info.file_version}")
        except AttributeError:
            # Safely handle the case where 'version' attribute is not present
            print("Warning: Version information not found in resources.")
    
    return version_info


def check_code_signatures(binary):
    signatures = []
    if isinstance(binary, lief.PE.Binary):
        if binary.has_signatures:
            for sig in binary.signatures:
                signer = sig.signer_info[0].issuer
                signatures.append(f"Signer: {signer}")
    elif isinstance(binary, lief.MachO.Binary):
        if binary.has_code_signature:
            signatures.append("Mach-O code signature found")
    return signatures

def analyze_binary(file_path):
    try:
        binary = lief.parse(file_path)
    except Exception as e:
        print(f"Error parsing binary: {e}")
        return

    print(f"Analyzing {file_path}...\n")

    # Debug Sections
    debug_sections = check_debug_sections(binary)
    if debug_sections:
        print(f"Debug sections found: {debug_sections}")

    # Debug Symbols
    debug_symbols = check_debug_symbols(binary)
    if debug_symbols:
        print(f"Debug symbols found: {debug_symbols}")

    # Suspicious Strings
    suspicious_strings = check_suspicious_strings(file_path)
    if suspicious_strings:
        print(f"Suspicious strings found: {suspicious_strings}")

    # Stripped Binary Check
    if check_stripped_binary(binary):
        print("Binary appears to be stripped (no symbols found).")
    else:
        print("Binary is not stripped (symbols remain).")

    # Timestamps
    timestamps = check_timestamps(binary)
    if timestamps:
        print(f"Timestamps found: {timestamps}")

    # Compiler Metadata
    compiler_metadata = check_compiler_metadata(file_path)
    if compiler_metadata:
        print(f"Compiler metadata found: {compiler_metadata}")

    # Version Info
    version_info = check_version_info(binary)
    if version_info:
        print(f"Version information found: {version_info}")

    # Code Signatures
    code_signatures = check_code_signatures(binary)
    if code_signatures:
        print(f"Code signatures found: {code_signatures}")

    # Platform-specific Checks
    if isinstance(binary, lief.PE.Binary):
        pdb_path = check_pdb_path(binary)
        if pdb_path:
            print(f"PDB path found: {pdb_path}")
    elif isinstance(binary, lief.ELF.Binary):
        pass  # Add ELF-specific checks if needed
    elif isinstance(binary, lief.MachO.Binary):
        pass  # Add Mach-O-specific checks if needed


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {os.path.basename(__file__)} <binary_file>")
        sys.exit(1)

    binary_file = sys.argv[1]
    if not os.path.exists(binary_file):
        print(f"File not found: {binary_file}")
        sys.exit(1)

    analyze_binary(binary_file)

