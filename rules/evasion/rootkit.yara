
rule linux_kernel_module_getdents64 : critical {
  meta:
    description = "kernel module that intercepts directory listing"
    ref = "https://github.com/m0nad/Diamorphine"
  strings:
    $getdents64 = "getdents64"
    $register_kprobe = "register_kprobe"
  condition:
    all of them
}

rule funky_high_signal_killer : suspicious {
  meta:
    description = "Uses high signals to communicate to a rootkit"
  strings:
    $odd_teen_sig = /kill -1[012346789]/ fullword
    $high_sig = /kill -[23456]\d/ fullword
  condition:
    any of them
}
