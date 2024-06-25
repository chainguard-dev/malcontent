
rule ptrace_injector : high {
  meta:
    description = "may inject code into other processes"
    hash_2024_procinject_infect = "cb7c09e58c5314e0429ace2f0e1f3ebd0b802489273e4b8e7531ea41fa107973"
  strings:
    $maps = /\/{0,1}proc\/[%{][%}\w]{0,1}\/maps/
    $ptrace = "ptrace" fullword
    $proc = "process" fullword
    $not_qemu = "QEMU_IS_ALIGNED"
    $not_chromium = "CHROMIUM_TIMESTAMP"
    $not_crashpad = "CRASHPAD" fullword
  condition:
    filesize < 67108864 and $maps and $ptrace and $proc and none of ($not*)
}
