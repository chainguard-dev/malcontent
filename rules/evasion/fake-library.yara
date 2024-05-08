
rule libnetresolv_fake_val : suspicious {
  meta:
    ref = "https://cert.gov.ua/article/6123309"
    description = "references fake library - possible dynamic library hijacking"
  strings:
    $libnetresolv = "libnetresolv.so"
  condition:
    any of them
}

rule libs_fake_val : suspicious {
  meta:
    ref = "https://cert.gov.ua/article/6123309"
    description = "references fake library, possible dynamic library hijacking"
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
  strings:
    $fake_libc_version = /libc.so.[2345789]/
  condition:
    any of them
}
