import winim

proc raiseException*(description: string) = 
  raise newException(OSError, description & " Errcode: " & $GetLastError())