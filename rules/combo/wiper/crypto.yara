
rule uname_hostname_encrypt_wipe_kill : suspicious {
  meta:
	description = "May encrypt, wipe files, and kill processes"
    hash_2023_Royal = "06abc46d5dbd012b170c97d142c6b679183159197e9d3f6a76ba5e5abf999725"
    hash_2023_blackcat_x64 = "45b8678f74d29c87e2d06410245ab6c2762b76190594cafc9543fb9db90f3d4f"
    hash_2021_miner_gkqjh = "00ae07c9fe63b080181b8a6d59c6b3b6f9913938858829e5a42ab90fb72edf7a"
    hash_2021_CoinMiner_TB_Camelot = "0ad6c635d583de499148b1ec46d8b39ae2785303e8b81996d3e9e47934644e73"
    hash_2021_Mettle = "1020ce1f18a2721b873152fd9f76503dcba5af7b0dd26d80fdb11efaf4878b1a"
    hash_2023_Linux_Malware_Samples_19f7 = "19f76bf2be3ea11732f2c5c562afbd6f363b062c25fba3a143c3c6ef4712774b"
    hash_2023_Linux_Malware_Samples_1ce9 = "1ce94d788d01ae70782084d5dd48844ecf03629c3aaacff7f4bc35e59d4aaf55"
    hash_2020_trojan_Meterpreter_Mettle_eukch = "24f3ac76dcd4b0830a1ebd82cc9b1abe98450b8df29cb4f18f032f1077d24404"
  strings:
    $encrypt = "encrypt" fullword
    $wipe = "wipe" fullword
    $processes = "processes" fullword
    $kill = "kill" fullword
    $uname = "uname" fullword
    $hostname = "hostname" fullword
  condition:
    all of them
}
