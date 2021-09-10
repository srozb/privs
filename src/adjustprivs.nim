import bitops
import winim
import winexception

proc setPrivilege*(hToken: HANDLE, privilege: string, bEnablePrivilege = true): bool =
  var tp: TOKEN_PRIVILEGES
  var luid: LUID
  let lpszPrivilege = privilege.LPCTSTR

  if bEnablePrivilege:
    echo "Enabling " & $lpszPrivilege & " privilege..."
  else:
    echo "Disabling " & $lpszPrivilege & " privilege..."

  let pval = LookupPrivilegeValue(NULL, lpszPrivilege, &luid)
  if pval < 0:
    raiseException("Privilege lookup failed.")

  tp.PrivilegeCount = 1
  tp.Privileges[0].Luid = luid
  if (bEnablePrivilege):
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
  else:
    tp.Privileges[0].Attributes = 0

  if (AdjustTokenPrivileges(hToken, FALSE, &tp, (sizeof(TOKEN_PRIVILEGES)).DWORD, (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL) < 0):
    raiseException("Adjusting token failed.")

  if (GetLastError() == ERROR_NOT_ALL_ASSIGNED):
    raiseException("Privilege not held by the process. Not elevated?")

  return true

proc getProcToken*(pid: int): HANDLE =
  let pid = pid.DWORD
  let hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)
  var hToken: HANDLE
  if (hProcess < 0):
    raiseException("OpenProcess() failed.")
  if (OpenProcessToken(hProcess,bitor(TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY), &hToken) < 0):
    raiseException("OpenProcessToken() failed.")
  return hToken

proc getParentPID*(): int =
  let pid = GetCurrentProcessId()
  var ppid = -1
  var h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
  var pe: PROCESSENTRY32
  pe.dwSize = (sizeof pe).DWORD
  if (Process32First(h, &pe) >= 0):
    while (Process32Next(h, &pe) >= 0):
      if (pe.th32ProcessID == pid):
        ppid = pe.th32ParentProcessID;
        break
  CloseHandle(h)
  return ppid

when isMainModule:
  let ppid = getParentPID()
  var hToken = getProcToken(ppid)

  discard setPrivilege(hToken, "SeRestorePrivilege", true)
  discard setPrivilege(hToken, "SeBackupPrivilege", true)
