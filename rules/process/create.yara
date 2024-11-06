rule _fork {
  meta:
    pledge      = "exec"
    syscall     = "fork"
    description = "create child process"
    ref         = "https://man7.org/linux/man-pages/man2/fork.2.html"

  strings:
    $fork = "_fork" fullword

  condition:
    any of them
}

rule fork {
  meta:
    pledge      = "exec"
    syscall     = "fork"
    description = "create child process"
    ref         = "https://man7.org/linux/man-pages/man2/fork.2.html"

  strings:
    $fork = "fork" fullword

  condition:
    any of them in (1000..3000)
}

rule syscall_vfork {
  meta:
    pledge      = "exec"
    syscall     = "vfork"
    description = "create child process"
    ref         = "https://man7.org/linux/man-pages/man2/vfork.2.html"

  strings:
    $vfork = "vfork" fullword

  condition:
    any of them
}

rule js_child_process: medium {
  meta:
    description = "create child process"

  strings:
    $child_process = /require\(['"]child_process['"]\)/

  condition:
    filesize < 1MB and any of them
}

rule syscall_clone: harmless {
  meta:
    pledge      = "exec"
    syscall     = "clone"
    description = "create child process"
    ref         = "https://man7.org/linux/man-pages/man2/clone.2.html"

  strings:
    $clone  = "clone" fullword
    $clone2 = "clone2" fullword
    $clone3 = "clone3" fullword

  condition:
    any of them
}

rule CreateProcess: low {
  meta:
    description = "create a new process"

  strings:
    $create = /CreateProcess\w{0,8}/

  condition:
    any of them
}
