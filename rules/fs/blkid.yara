rule blkid: linux {
  meta:
    description = "works with block device attributes"
    ref         = "https://man7.org/linux/man-pages/man8/blkid.8.html"

  strings:
    $ref = "blkid" fullword

  condition:
    any of them
}
