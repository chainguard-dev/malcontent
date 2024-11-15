rule DADisk: medium {
  meta:
    description = "Get information about disks"
    ref         = "https://developer.apple.com/documentation/diskarbitration"
    platforms   = "darwin"

  strings:
    $ref  = "DADiskCopyDescription" fullword
    $ref2 = "DADiskCreateFromBSDNAme" fullword
    $ref3 = "gopsutil/v3/disk"
    $ref4 = "DiskFreeSpace" fullword

  condition:
    any of them
}
