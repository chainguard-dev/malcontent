rule var_tmp_path: medium {
  meta:
    description                          = "path reference within /var/tmp"
    hash_2023_Downloads_6e35             = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
    hash_2024_Downloads_e70e             = "e70e96983734ee23e52391aa96d30670b2dcebb0cbca46c8eddb014f450c661f"
    hash_2023_Linux_Malware_Samples_0638 = "063830221431f8136766f2d740df6419c8cd2f73b10e07fa30067df506592210"

  strings:
    $resolv = /var\/tmp\/[%\w\.\-\/]{0,64}/

  condition:
    any of them
}

