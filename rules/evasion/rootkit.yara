
rule linux_kernel_module_getdents64 : critical {
  meta:
    description = "kernel module that intercepts directory listing"
    ref = "https://github.com/m0nad/Diamorphine"
    hash_2022_LQvKibDTq4_diamorphine = "aec68cfa75b582616c8fbce22eecf463ddb0c09b692a1b82a8de23fb0203fede"
    hash_2023_LQvKibDTq4_diamorphine = "e93e524797907d57cb37effc8ebe14e6968f6bca899600561971e39dfd49831d"
    hash_2023_LQvKibDTq4_diamorphine = "d83f43f47c1438d900143891e7a542d1d24f9adcbd649b7698d8ee7585068039"
  strings:
    $getdents64 = "getdents64"
    $register_kprobe = "register_kprobe"
  condition:
    all of them
}

rule funky_high_signal_killer : high {
  meta:
    description = "Uses high signals to communicate to a rootkit"
    hash_2023_Qubitstrike_branch_raw_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
    hash_2023_Qubitstrike_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
  strings:
    $odd_teen_sig = /kill -1[012346789]/ fullword
    $high_sig = /kill -[23456]\d/ fullword
  condition:
    any of them
}
