rule libnetresolv_fake_val: high {
  meta:
    ref         = "https://cert.gov.ua/article/6123309"
    description = "references fake library - possible dynamic library hijacking"

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

  strings:
    $ref            = /libc.so.[234589]/
    $not_go_example = "libc.so.96.1"

  condition:
    $ref and none of ($not*)
}

