import winim except CreateFile
import winexception

proc CreateFile(lpFileName: LPCSTR, dwDesiredAccess: DWORD, dwShareMode: DWORD, lpSecurityAttributes: LPSECURITY_ATTRIBUTES, dwCreationDisposition: DWORD, dwFlagsAndAttributes: DWORD, hTemplateFile: typeof(nil)): HANDLE {.winapi, stdcall, dynlib: "kernel32", importc: "CreateFileA".}

proc restoreFile*(filename: string, pBuf: ptr char, buflen: int): bool =
  var 
    dHandle: HANDLE
    destFile = filename.LPCSTR
    bytesWritten: DWORD

  dHandle = CreateFile(
    destFile,
    GENERIC_WRITE,
    FILE_SHARE_WRITE,
    NULL,
    CREATE_ALWAYS,
    FILE_FLAG_BACKUP_SEMANTICS,
    NULL
  )
  if (dHandle == INVALID_HANDLE_VALUE):
    raiseException("Unable to obtain file handle.")
    return false

  WriteFile(
    dHandle,
    pBuf,
    buflen.DWORD,
    &bytesWritten,
    NULL
  )
  CloseHandle(dHandle)

  return true
