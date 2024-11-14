rule execall: medium {
  meta:
    syscall     = "execve"
    pledge      = "exec"
    description = "executes external programs"

  strings:
    $execl  = "execl" fullword
    $execle = "execle" fullword
    $execlp = "execlp" fullword
    $execv  = "execv" fullword
    $execvp = "execvp" fullword
    $execvP = "execvP" fullword
    $go     = "syscall.libc_execve_trampoline"

  condition:
    any of ($exec*) and not $go
}

rule execve: medium {
  meta:
    syscall                  = "execve"
    pledge                   = "exec"
    description              = "executes external programs"
    hash_2024_Downloads_036a = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"
    hash_2024_Downloads_0ca7 = "0ca7e0eddd11dfaefe0a0721673427dd441e29cf98064dd0f7b295eae416fe1b"

  strings:
    $execve   = "execve" fullword
    $go       = "syscall.libc_execve_trampoline"
    $execve_f = "fexecve" fullword

  condition:
    any of ($exec*) and not $go
}

rule exec_cmd_run: medium {
  meta:
    syscall     = "execve"
    pledge      = "exec"
    description = "executes external programs"

  strings:
    $ref  = "exec.(*Cmd).Run"
    $ref2 = ").CombinedOutput"

  condition:
    any of them
}

rule perl_system: medium {
  meta:
    syscall                     = "execve"
    pledge                      = "exec"
    description                 = "executes external programs"
    hash_1979_FruitFly_B_fpsaud = "befa9bfe488244c64db096522b4fad73fc01ea8c4cd0323f1cbdee81ba008271"

    hash_2024_raas_raas_test = "58829e93da60b0934d7739d1a6aba92d665ac72bab9efc0571c0fc9751d40f3e"

  strings:
    $system = /system\([\"\'\w\ \-\)\/]{0,64}/
    $perl   = "perl" fullword

  condition:
    filesize < 65535 and $perl and $system
}

rule ruby_system: medium {
  meta:
    description = "executes external program"

  strings:
    $system  = /system\(.{1,32}\)/
    $require = "require" fullword

  condition:
    filesize < 65535 and $require and $system
}

rule py_subprocess: medium {
  meta:
    syscall                             = "execve"
    pledge                              = "exec"
    description                         = "execute external program"
    ref                                 = "https://man7.org/linux/man-pages/man2/execve.2.html"
    hash_2022_2022_requests_3_0_0_setup = "15507092967fbd28ccb833d98c2ee49da09e7c79fd41759cd6f783672fe1c5cc"
    hash_2023_grandmask_3_13_setup      = "8835778f9e75e6493693fc6163477ec94aba723c091393a30d7e7b9eed4f5a54"

  strings:
    $naked        = "subprocess"
    $val          = /subprocess\.\w{1,16}[\(\"\/\w\'\.\- \,\[\]\/\{\}]{0,64}/
    $os_system    = /os.system\([\"\'\w\. \-\)\/\{\}]{0,64}/
    $os_startfile = /os.startfile\(.{0,64}/

  condition:
    any of them
}

rule subprocess: medium {
  meta:
    syscall                  = "execve"
    pledge                   = "exec"
    description              = "execute external program"
    ref                      = "https://man7.org/linux/man-pages/man2/execve.2.html"
    hash_2023_Downloads_e6b6 = "e6b6cf40d605fc7a5e8ba168a8a5d8699b0879e965d2b803e29b87926cba861f"

  strings:
    $naked = "subprocess"
    $val   = /subprocess\.\w{1,16}[\(\"\/\w\'\.\- \,\[\]]{0,64}/

  condition:
    any of them
}

rule posix_spawn: medium {
  meta:
    syscall                  = "posix_spawn"
    pledge                   = "exec"
    description              = "spawn a process"
    ref                      = "https://man7.org/linux/man-pages/man3/posix_spawn.3.html"
    hash_2023_Downloads_016a = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2023_Downloads_45b8 = "45b8678f74d29c87e2d06410245ab6c2762b76190594cafc9543fb9db90f3d4f"

  strings:
    $ref = "posix_spawn"

  condition:
    all of them
}

rule go_exec: medium {
  meta:
    syscall     = "posix_spawn"
    pledge      = "exec"
    description = "run external command"
    ref         = "https://pkg.go.dev/os/exec"

  strings:
    $ref = "exec_unix.go"

  condition:
    all of them
}

rule npm_exec: medium {
  meta:
    syscall                 = "posix_spawn"
    pledge                  = "exec"
    description             = "spawn a process"
    ref                     = "https://nodejs.org/api/child_process.html"
    hash_2023_misc_mr_robot = "630bbcf0643d9fc9840f2f54ea4ae1ea34dc94b91ee011779c8e8c91f733c9f5"

    hash_2015_scripts_preinstall = "b5fa20b9c699995990ca3af5bd4a5d76da12c125c541f33ac2b61990b16d353c"

  strings:
    $child   = "child_process"
    $ref_val = /exec\([\'\"][\w \/\'\)]{0,64}/

  condition:
    all of them
}
