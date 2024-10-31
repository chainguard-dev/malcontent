
rule vm_checker : medium {
  meta:
    description = "Checks to see if it is running with a VM"
    hash_2024_Downloads_3105 = "31054fb826b57c362cc0f0dbc8af15b22c029c6b9abeeee9ba8d752f3ee17d7d"
    hash_2023_Downloads_589d = "589dbb3f678511825c310447b6aece312a4471394b3bc40dde6c75623fc108c0"
    hash_2023_Downloads_Chrome_Update = "eed1859b90b8832281786b74dc428a01dbf226ad24b182d09650c6e7895007ea"
  strings:
    $a_vmware = "VMware"
    $a_qemu = "QEMU Virtual CPU"
    $a_apple_vm = "Apple Virtual Machine"
    $a_intel = "GenuineIntel"
    $a_amd = "GenuineAMD"
    $not_qemu_console = "QEMU_CONSOLE"
    $not_qemu = "QEMU v"
    $not_fabrice = "Fabrice Bellard"
    $not_nuclei = "NUCLEI_TEMPLATES"
  condition:
    2 of ($a_*) and none of ($not_*)
}
