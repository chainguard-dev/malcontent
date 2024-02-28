rule libnetresolv_fake : suspicious {
  meta:
    ref = "https://cert.gov.ua/article/6123309"
	description = "References fake library - libnetresolv.so"
  strings:
    $libnetresolv = "libnetresolv.so"
  condition:
    any of them
}

rule libs_fake : suspicious {
  meta:
    ref = "https://cert.gov.ua/article/6123309"
	description = "References fake library - libs.so"
  strings:
    $libnetresolv = "libs.so" fullword
  condition:
    any of them
}


rule libc_fake_number : suspicious {
  meta:
    ref = "https://cert.gov.ua/article/6123309"
	description = "References a non-standard libc library (normally libc.so.6)"
  strings:
    $fake_libc_version = /libc.so.[02345789]/
  condition:
    any of them
}
