rule usr_local_path: harmless {
  meta:
    description = "path reference within /usr/local"

  strings:
    $val = /\/usr\/local\/[\w\.\-\/]{0,64}/
    $go  = "/usr/local/go"

  condition:
    $val and not $go
}

rule usr_local_bin_path: medium {
  meta:
    description                                                                          = "path reference within /usr/local/bin"
    hash_2023_Downloads_311c                                                             = "311c93575efd4eeeb9c6674d0ab8de263b72a8fb060d04450daccc78ec095151"
    hash_2024_Downloads_4ba700b0e86da21d3dcd6b450893901c252bf817bd8792548fc8f389ee5aec78 = "fd3e21b8e2d8acf196cb63a23fc336d7078e72c2c3e168ee7851ea2bef713588"
    hash_2023_Downloads_d920                                                             = "d920dec25946a86aeaffd5a53ce8c3f05c9a7bac44d5c71481f497de430cb67e"

  strings:
    $val = /\/usr\/local\/bin[\w\.\-\/]{0,64}/

  condition:
    $val
}

rule usr_local_lib_path: medium {
  meta:
    description                          = "path reference within /usr/local/lib"
    hash_2024_Downloads_0f66             = "0f66a4daba647486d2c9d838592cba298df2dbf38f2008b6571af8a562bc306c"
    hash_2023_Downloads_6e35             = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
    hash_2023_Linux_Malware_Samples_00ae = "00ae07c9fe63b080181b8a6d59c6b3b6f9913938858829e5a42ab90fb72edf7a"

  strings:
    $val = /\/usr\/local\/lib[\w\.\-\/]{0,64}/

  condition:
    $val
}
