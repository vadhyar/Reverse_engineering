# TODO: This script extracts API hashes and compares them to DLL exports.
# @author Sai Bharath Vadhyar
# @category GhidraTHON Scripts
# @keybinding 
# @menupath 
# @toolbar 

import pefile
import json
from javax.swing import JOptionPane

def api_hash_database(start_address, memory, size):
    stored_api_hashes = []
    for b in range(0, int(size), 4):
        dword_address = start_address.add(b)
        dword_value = memory.getInt(dword_address)
        unsigned_dword_value = dword_value & 0xFFFFFFFF
        stored_api_hashes.append(hex(unsigned_dword_value))
    return stored_api_hashes

def function_exports(DLL_s):
    exports_directory = {}
    for dll in DLL_s:
        path = rf"C:\Windows\System32\{dll}"
        exports_directory[f'{dll}'] = []    
        try:
            pe = pefile.PE(path)
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                for syms in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    exports_directory[dll].append(syms.name.decode('utf-8'))
        except Exception as e:
            print(f"Error processing {dll}: {e}")  # Log errors for debugging
    return exports_directory

def function_hashes(exports_directory):
    hash_map = {}
    for dll, function_list in exports_directory.items():
        if not function_list:
            continue
        for function_name in function_list:
            result = 0x2b
            for f in function_name:
                result = ord(f) + 0x10f * result
            result = result & 0x1fffff
            hash_map[f'{hex(result)}'] = function_name
    return hash_map

def calculated_hashes(stored_hashes):
    final_stored_hash_db = {}
    for api_hash in stored_hashes:
        api_hash_int=int(api_hash,16)
        shift_left_xor = api_hash_int ^ (api_hash_int << 16) ^ 0xBD65DD34
        hash_low_order_bytes = shift_left_xor & 0x1fffff
        final_stored_hash_db[hash_low_order_bytes] = api_hash
    return final_stored_hash_db

def compare_hashes(final_stored_hash_db, func_hashes):
    import_table = {}
    for c_hash, st_hashes in final_stored_hash_db.items():
        if hex(c_hash) in func_hashes:
            import_table[st_hashes] = func_hashes[hex(c_hash)]
    return import_table

def main():
    # Directly check the currentProgram
    if currentProgram is None:
        print("No current program is loaded.")
        return
    
    # List of DLLs to check for exports
    DLL_s = [
        "kernel32.dll",
        "user32.dll",
        "advapi32.dll",
        "ws2_32.dll",
        "mswsock.dll",
        "shell32.dll",
        "ntdll.dll",
        "gdi32.dll",
        "comdlg32.dll",
        "ole32.dll",
        "crypt32.dll",
        "rpcrt4.dll",
        "iphlpapi.dll",
        "shlwapi.dll",
        "mspmsnsv.dll",
        "urlmon.dll",
        "wininet.dll",
        "dbghelp.dll",
        "d3dx9.dll",
        "winsock.dll",
        "cmd.exe",
        "powershell.exe",
        "rundll32.exe",
        "svchost.exe",
        "wscript.exe",
        "taskkill.exe",
        "tasklist.exe",
        "sc.exe",
        "at.exe"
    ]

    # Getting user inputs for the memory address and size
    arrayAddress = JOptionPane.showInputDialog(None, "Enter the address of the array:", "Array Address Input", JOptionPane.QUESTION_MESSAGE)
    size = JOptionPane.showInputDialog(None, "Enter the size:", "Length of the String", JOptionPane.QUESTION_MESSAGE)

    # Validate and convert inputs
    try:
        start_address = toAddr(arrayAddress)
        size = int(size)
    except ValueError:
        JOptionPane.showMessageDialog(None, "Invalid input! Please enter valid numbers.", "Error", JOptionPane.ERROR_MESSAGE)
        return

    # Directly use currentProgram to access memory
    memory = currentProgram().getMemory()
    
    # Fetch API hashes from the specified memory address
    stored_hashes = api_hash_database(start_address, memory, size)

    # Retrieve exported functions from DLLs
    func_exports = function_exports(DLL_s)

    # Generate function hashes based on the exported functions
    func_hashes = function_hashes(func_exports)

    # Calculate the final hashes for comparison
    final_stored_hash_db = calculated_hashes(stored_hashes)

    # Compare calculated hashes with the function hashes
    func_resolve = compare_hashes(final_stored_hash_db, func_hashes)

    # Output the results to a JSON file
    json_object = json.dumps(func_resolve, indent=4)
    with open(r"C:\Users\REM\Desktop\import_address_table.json", "w") as outfile:
        outfile.write(json_object)

if __name__ == '__main__':
    main()
