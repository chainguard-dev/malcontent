rule DADisk: medium {
  meta:
    description                          = "Get information about disks"
    ref                                  = "https://developer.apple.com/documentation/diskarbitration"
    platforms                            = "darwin"
    hash_2022_CloudMensis_WindowServer   = "317ce26cae14dc9a5e4d4667f00fee771b4543e91c944580bbb136e7fe339427"
    hash_2022_CloudMensis_WindowServer_2 = "b8a61adccefb13b7058e47edcd10a127c483403cf38f7ece126954e95e86f2bd"
    hash_2024_2024_Previewers            = "20b986b24d86d9a06746bdb0c25e21a24cb477acb36e7427a8c465c08d51c1e4"

  strings:
    $ref  = "DADiskCopyDescription" fullword
    $ref2 = "DADiskCreateFromBSDNAme" fullword

  condition:
    any of them
}
