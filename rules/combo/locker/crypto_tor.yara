
rule crypto_locker {
  meta:
    ref = "https://www.sentinelone.com/blog/dark-angels-esxi-ransomware-borrows-code-victimology-from-ragnarlocker/"
    hash_2023_Downloads_24b5 = "24b5cdfc8de10c99929b230f0dcbf7fcefe9de448eeb6c75675cfe6c44633073"
    hash_2023_Linux_Malware_Samples_83c7 = "83c771f927a0a5faf6f6acd88ed9db800b993f25df22468b394725bd4cca4fcf"
    hash_2020_IPStorm_IPStorm_unpacked = "522a5015d4d11833ead6d88d4405c0f4119ff29b1f64b226c464e958f03e1434"
    hash_2023_UPX_0c25a05bdddc144fbf1ffa29372481b50ec6464592fdfb7dec95d9e1c6101d0d_elf_x86_64 = "818b80a08418f3bb4628edd4d766e4de138a58f409a89a5fdba527bab8808dd2"
    hash_2023_OK_ad69 = "ad69e198905a8d4a4e5c31ca8a3298a0a5d761740a5392d2abb5d6d2e966822f"
    hash_2023_Sysrv_Hello_sys_x86_64 = "cd784dc1f7bd95cac84dc696d63d8c807129ef47b3ce08cd08afb7b7456a8cd3"
    hash_2023_Downloads_24b5 = "24b5cdfc8de10c99929b230f0dcbf7fcefe9de448eeb6c75675cfe6c44633073"
    hash_2023_Unix_Ransomware_Ech0raix_3d8d = "3d8d25e2204f25260c42a29ad2f6c5c21f18f90ce80cb338bc678e242fba68cd"
  strings:
    $c_locked = "locked" fullword
    $c_kill = "kill" fullword
    $c_Path = "Path" fullword
    $c_Lock_file = "Lock" fullword
    $c_Files_Found = "Files Found"
    $c_README = "README" fullword
    $c_Done = "Done" fullword
    $c_encrypt = "encrypt" fullword
    $c_Queue = "Queue" fullword
    $c_Round = "Round" fullword
    $c_cores = "cores" fullword

	$x_browser = "TOR Browser" nocase
    $x_tor = " TOR "
    $x_download = "torproject.org"
    $x_onion = /\w\.onion\W/
	$x_btc = "BTC" fullword

	$not_xul = "XUL_APP_FILE"
  condition:
    5 of ($c*) and 2 of ($x*) and none of ($not*)
}
