
rule execall : medium {
  meta:
    syscall = "execve"
    pledge = "exec"
    description = "executes external programs"
    hash_2023_Downloads_016a = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2024_Downloads_036a = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"
    hash_2023_Downloads_06ab = "06abc46d5dbd012b170c97d142c6b679183159197e9d3f6a76ba5e5abf999725"
  strings:
    $execl = "execl" fullword
    $execle = "execle" fullword
    $execlp = "execlp" fullword
    $execv = "execv" fullword
    $execvp = "execvp" fullword
    $execvP = "execvP" fullword
    $go = "syscall.libc_execve_trampoline"
  condition:
    any of ($exec*) and not $go
}

rule execve : medium {
  meta:
    syscall = "execve"
    pledge = "exec"
    description = "executes external programs"
    hash_2024_Downloads_036a = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"
    hash_2024_Downloads_0ca7 = "0ca7e0eddd11dfaefe0a0721673427dd441e29cf98064dd0f7b295eae416fe1b"
    hash_2024_Downloads_4ba700b0e86da21d3dcd6b450893901c252bf817bd8792548fc8f389ee5aec78 = "fd3e21b8e2d8acf196cb63a23fc336d7078e72c2c3e168ee7851ea2bef713588"
  strings:
    $execve = "execve" fullword
    $go = "syscall.libc_execve_trampoline"
    $execve_f = "fexecve" fullword
  condition:
    any of ($exec*) and not $go
}

rule exec_cmd_run : medium {
  meta:
    syscall = "execve"
    pledge = "exec"
    description = "executes external programs"
    hash_2023_Downloads_21b3 = "21b3e304db526e2c80df1f2da2f69ab130bdad053cb6df1e05eb487a86a19b7c"
    hash_2023_Downloads_21ca = "21ca44d382102e0ae33d02f499a5aa2a01e0749be956cbd417aae64085f28368"
    hash_2023_Downloads_24b5 = "24b5cdfc8de10c99929b230f0dcbf7fcefe9de448eeb6c75675cfe6c44633073"
  strings:
    $ref = "exec.(*Cmd).Run"
    $ref2 = ").CombinedOutput"
  condition:
    any of them
}

rule perl_system : notable {
  meta:
    syscall = "execve"
    pledge = "exec"
    description = "executes external programs"
  strings:
    $system = /system\([\"\'\w\ \-\)\/]{0,64}/
    $perl = "perl" fullword
  condition:
    filesize < 65535 and $perl and $system
}

rule py_subprocess : notable {
  meta:
    syscall = "execve"
    pledge = "exec"
    description = "execute external program"
    ref = "https://man7.org/linux/man-pages/man2/execve.2.html"
    hash_2022_2022_requests_3_0_0_setup = "15507092967fbd28ccb833d98c2ee49da09e7c79fd41759cd6f783672fe1c5cc"
    hash_2023_grandmask_3_13_setup = "8835778f9e75e6493693fc6163477ec94aba723c091393a30d7e7b9eed4f5a54"
    hash_2023_libgrandrandomintel_3_58_setup = "cd211e0f8d84100b1b4c1655e913f40a76beaacc482e751e3a7c7ed126fe1a90"
  strings:
    $naked = "subprocess"
    $val = /subprocess\.\w{1,16}[\(\"\/\w\'\.\- \,\[\]]{0,64}/
    $os_system = /os.system\([\"\'\w\ \-\)\/]{0,64}/
  condition:
    any of them
}

rule subprocess : medium {
  meta:
    syscall = "execve"
    pledge = "exec"
    description = "execute external program"
    ref = "https://man7.org/linux/man-pages/man2/execve.2.html"
    hash_2023_Downloads_e6b6 = "e6b6cf40d605fc7a5e8ba168a8a5d8699b0879e965d2b803e29b87926cba861f"
    hash_2023_Linux_Malware_Samples_03bb = "03bb1cfd9e45844701aabc549f530d56f162150494b629ca19d83c1c696710d7"
    hash_2023_Linux_Malware_Samples_05ca = "05ca0e0228930e9ec53fe0f0b796255f1e44ab409f91bc27d20d04ad34dcb69d"
  strings:
    $naked = "subprocess"
    $val = /subprocess\.\w{1,16}[\(\"\/\w\'\.\- \,\[\]]{0,64}/
  condition:
    any of them
}

rule posix_spawn : medium {
  meta:
    syscall = "posix_spawn"
    pledge = "exec"
    description = "spawn a process"
    ref = "https://man7.org/linux/man-pages/man3/posix_spawn.3.html"
    hash_2023_Downloads_016a = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2023_Downloads_45b8 = "45b8678f74d29c87e2d06410245ab6c2762b76190594cafc9543fb9db90f3d4f"
    hash_2023_Downloads_Brawl_Earth = "fe3ac61c701945f833f218c98b18dca704e83df2cf1a8994603d929f25d1cce2"
  strings:
    $ref = "posix_spawn"
  condition:
    all of them
}

rule go_exec : medium {
  meta:
    syscall = "posix_spawn"
    pledge = "exec"
    description = "run external command"
    ref = "https://pkg.go.dev/os/exec"
    hash_2023_Downloads_21b3 = "21b3e304db526e2c80df1f2da2f69ab130bdad053cb6df1e05eb487a86a19b7c"
    hash_2023_Downloads_21ca = "21ca44d382102e0ae33d02f499a5aa2a01e0749be956cbd417aae64085f28368"
    hash_2023_Downloads_24b5 = "24b5cdfc8de10c99929b230f0dcbf7fcefe9de448eeb6c75675cfe6c44633073"
  strings:
    $ref = "exec_unix.go"
  condition:
    all of them
}

rule npm_exec : medium {
  meta:
    syscall = "posix_spawn"
    pledge = "exec"
    description = "spawn a process"
    ref = "https://nodejs.org/api/child_process.html"
    hash_2023_misc_mr_robot = "630bbcf0643d9fc9840f2f54ea4ae1ea34dc94b91ee011779c8e8c91f733c9f5"
    hash_2024_2021_ua_parser_js_preinstall = "62e08e4967da57e037255d2e533b7c5d7d1f1773af2a06113470c29058b5fcd0"
  strings:
    $child = "child_process"
    $ref_val = /exec\([\'\"][\w \/\'\)]{0,64}/
  condition:
    all of them
}
