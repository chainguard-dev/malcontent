rule vm_checker: medium {
  meta:
    description = "Checks to see if it is running with a VM"

  strings:
    $a_vmware         = "VMware"
    $a_qemu           = "QEMU Virtual CPU"
    $a_apple_vm       = "Apple Virtual Machine"
    $a_intel          = "GenuineIntel"
    $a_amd            = "GenuineAMD"
    $not_qemu_console = "QEMU_CONSOLE"
    $not_qemu         = "QEMU v"
    $not_fabrice      = "Fabrice Bellard"
    $not_nuclei       = "NUCLEI_TEMPLATES"

  condition:
    2 of ($a_*) and none of ($not_*)
}
