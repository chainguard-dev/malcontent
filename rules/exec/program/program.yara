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
    syscall     = "execve"
    pledge      = "exec"
    description = "executes external programs"

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
    syscall     = "execve"
    pledge      = "exec"
    description = "executes external programs"

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
    $f_system = /system\(.{1,32}\)/ fullword
    $f_exec   = /exec\(.{1,32}\)/ fullword
    $require  = "require" fullword

  condition:
    filesize < 65535 and $require and any of ($f*)
}

rule ruby_system_execdir: high {
  meta:
    description = "executes external program from unusual directory"

  strings:
    $tmp          = /system\(['"]\/tmp\/[\w\. -]{1,32}/
    $var_tmp      = /system\(['"]\/var\/tmp\/[\w\. -]{1,32}/
    $exec_tmp     = /exec\(['"]\/tmp\/[\w\. -]{1,32}/
    $exec_var_tmp = /exec\(['"]\/var\/tmp\/[\w\. -]{1,32}/

  condition:
    filesize < 1MB and any of them
}

rule py_subprocess: medium {
  meta:
    syscall     = "execve"
    pledge      = "exec"
    description = "execute external program"
    ref         = "https://man7.org/linux/man-pages/man2/execve.2.html"

  strings:
    $naked        = "subprocess"
    $val          = /subprocess\.\w{1,16}.{0,96}/
    $os_system    = /os.system\(.{0,96}/
    $os_startfile = /os.startfile\(.{0,96}/

  condition:
    any of them
}

rule subprocess: medium {
  meta:
    syscall     = "execve"
    pledge      = "exec"
    description = "execute external program"
    ref         = "https://man7.org/linux/man-pages/man2/execve.2.html"

  strings:
    $naked = "subprocess"
    $val   = /subprocess\.\w{1,16}[\(\"\/\w\'\.\- \,\[\]]{0,64}/

  condition:
    any of them
}

rule posix_spawn: medium {
  meta:
    syscall     = "posix_spawn"
    pledge      = "exec"
    description = "spawn a process"
    ref         = "https://man7.org/linux/man-pages/man3/posix_spawn.3.html"

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
    syscall     = "posix_spawn"
    pledge      = "exec"
    description = "spawn a process"
    ref         = "https://nodejs.org/api/child_process.html"

  strings:
    $child   = "child_process"
    $ref_val = /exec\([\'\"][\w \/\'\)]{0,64}/

  condition:
    all of them
}

rule hash_bang_bash_exec: high {
  meta:
    description = "starts program from a hash-bang line"

  strings:
    $bin_bash = /#!\/bin\/bash\s{1,256}\/[\w\/\.\-]{2,64}/

  condition:
    all of them and $bin_bash at 0
}

rule hash_bang_sh_exec: high {
  meta:
    description = "starts program from a hash-bang line"

  strings:
    $bin_sh = /#!\/bin\/sh\s{1,256}\/[\w\/\.\-]{2,64}/

  condition:
    all of them and $bin_sh at 0
}
