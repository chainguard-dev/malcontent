rule var_log_path: medium {
  meta:
    description                          = "path reference within /var/log"
    hash_2023_Downloads_6e35             = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
    hash_2023_Linux_Malware_Samples_0638 = "063830221431f8136766f2d740df6419c8cd2f73b10e07fa30067df506592210"
    hash_2023_Linux_Malware_Samples_1f94 = "1f94aa7ad1803a08dab3442046c9d96fc3d19d62189f541b07ed732e0d62bf05"

  strings:
    $ref = /\/var\/log\/[\%\w\.\-\/]{4,32}/ fullword

  condition:
    $ref
}
