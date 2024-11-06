rule vmware_vms: medium {
  meta:
    description = "gets a list of VMware VM IDs"

  strings:
    $ref  = "vim-cmd"
    $ref2 = "vmsvc"
    $ref3 = "getallvm"

  condition:
    all of them
}
