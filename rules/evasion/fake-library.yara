
rule libnetresolv_fake_val : suspicious {
  meta:
    ref = "https://cert.gov.ua/article/6123309"
    description = "references fake library - possible dynamic library hijacking"
    hash_2023_Qubitstrike_branch_raw_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
    hash_2023_Qubitstrike_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
  strings:
    $libnetresolv = "libnetresolv.so"
  condition:
    any of them
}

rule libs_fake_val : suspicious {
  meta:
    ref = "https://cert.gov.ua/article/6123309"
    description = "references fake library, possible dynamic library hijacking"
    hash_2023_uacert_refs = "106eef08f3bfcced3e221ee6f789792650386d7794d30c80eae19e42ef893682"
  strings:
    $libnetresolv = "libs.so" fullword
  condition:
    any of them
}

rule libc_fake_number_val : suspicious {
  meta:
    ref = "https://cert.gov.ua/article/6123309"
    description = "references a non-standard libc library (normally libc.so.6)"
    hash_2023_ZIP_locker_FreeBSD_64 = "41cbb7d79388eaa4d6e704bd4a8bf8f34d486d27277001c343ea3ce112f4fb0d"
    hash_2023_uacert_refs = "106eef08f3bfcced3e221ee6f789792650386d7794d30c80eae19e42ef893682"
  strings:
    $fake_libc_version = /libc.so.[2345789]/
  condition:
    any of them
}
