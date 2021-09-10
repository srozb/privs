# Package

version       = "0.1.0"
author        = "Sławomir Rozbicki"
description   = "Manipulate Windows processes privileges"
license       = "MIT"
srcDir        = "src"
bin           = @["privs"]


# Dependencies

requires "nim >= 1.4.8, winim, cligen"
