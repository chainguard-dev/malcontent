rule proc_s_exe: high {
  meta:
    description = "accesses underlying executable of other processes"

  strings:
    $string   = "/proc/%s/exe" fullword
    $not_tool = /[Uu]sage:/ fullword

  condition:
    $string and none of ($not*)
}

rule proc_d_exe: medium {
  meta:
    description = "accesses underlying executable of other processes"

  strings:
    $digit    = "/proc/%d/exe" fullword
    $not_tool = /[Uu]sage:/ fullword

  condition:
    // the help-text marker is the only conclusive CLI-tool signal here; a bare
    // "cgroup" mention used to exempt the file on its own, which is trivial to add
    $digit and none of ($not*)
}

rule proc_d_exe_high: high {
  meta:
    description = "accesses underlying executable of other processes"

  strings:
    $ref = "/proc/%d/exe" fullword

    $o_sign      = "/etc/init.d"
    $o_net_dev   = "/proc/net/dev"
    $o_bash      = "/bin/bash"
    $o_tty       = "/dev/tty"
    $o_var_tmp   = "/var/tmp"
    $o_osrelease = "/proc/sys/kernel/osrelease"

  condition:
    filesize < 5MB and $ref and any of ($o*)
}

rule proc_py_exe: high {
  meta:
    description = "accesses underlying executable of other processes"

  strings:
    $python = "/proc/{}/exe" fullword

  condition:
    any of them
}

rule legit_proc_exec: override {
  meta:
    proc_exe = "medium"

  strings:
    $string = "Fastfetch" fullword

  condition:
    filesize < 3MB and any of them
}
