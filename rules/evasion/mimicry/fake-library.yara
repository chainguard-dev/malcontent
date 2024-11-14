rule libnetresolv_fake_val: high {
  meta:
    ref         = "https://cert.gov.ua/article/6123309"
    description = "references fake library - possible dynamic library hijacking"

    hash_2023_Qubitstrike_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"

  strings:
    $libnetresolv = "libnetresolv.so"

  condition:
    any of them
}

rule libs_fake_val: high {
  meta:
    ref         = "https://cert.gov.ua/article/6123309"
    description = "references fake library, possible dynamic library hijacking"

  strings:
    $libnetresolv = "libs.so" fullword

  condition:
    any of them
}

rule libc_fake_number_val: high {
  meta:
    ref         = "https://cert.gov.ua/article/6123309"
    description = "references a non-standard libc library (normally libc.so.6)"

    hash_2023_uacert_refs = "106eef08f3bfcced3e221ee6f789792650386d7794d30c80eae19e42ef893682"

  strings:
    $ref            = /libc.so.[2345789]/
    $not_go_example = "libc.so.96.1"

  condition:
    $ref and none of ($not*)
}

