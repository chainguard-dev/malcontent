
rule uname_hostname_encrypt_wipe_kill : suspicious {
  meta:
    description = "May encrypt, wipe files, and kill processes"
    hash_2023_ZIP_locker_Apple_M1_64 = "3e4bbd21756ae30c24ff7d6942656be024139f8180b7bddd4e5c62a9dfbd8c79"
    hash_2023_ZIP_locker_FreeBSD_64 = "41cbb7d79388eaa4d6e704bd4a8bf8f34d486d27277001c343ea3ce112f4fb0d"
    hash_2023_ZIP_locker_MIPS64N_32 = "2f31962c5e89917f6df87babd836840042b7ea7ea01763cff1bf645878a2ab47"
  strings:
    $encrypt = "encrypt" fullword
    $wipe = "wipe" fullword
    $processes = "processes" fullword
    $kill = "kill" fullword
    $uname = "uname" fullword
    $hostname = "hostname" fullword
  condition:
    filesize < 67108864 and all of them
}
