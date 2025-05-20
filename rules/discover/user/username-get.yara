include "rules/global/global.yara"

rule getlogin {
  meta:
    syscall     = "getlogin"
    description = "get login name"
    pledge      = "id"
    ref         = "https://linux.die.net/man/3/getlogin"

  strings:
    $ref  = "getlogin" fullword
    $ref2 = "getpass.getuser" fullword

  condition:
    any of them
}

rule whoami: medium {
  meta:
    syscall     = "getuid"
    description = "returns the user name running this process"
    ref         = "https://man7.org/linux/man-pages/man1/whoami.1.html"

  strings:
    $ref  = "whoami" fullword
    $ref2 = "NSUserName" fullword

  condition:
    any of them
}

rule pysetup_gets_login: high {
  meta:
    description = "Python library installer gets login information"
    filetypes   = "py"

  strings:
    $ref  = "os.getlogin" fullword
    $ref2 = "getpass.getuser" fullword
    $ref3 = "whoami" fullword

  condition:
    global_python_setup and any of them
}
