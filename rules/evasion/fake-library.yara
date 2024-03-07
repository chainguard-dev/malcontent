rule libnetresolv_fake : suspicious {
  meta:
    ref = "https://cert.gov.ua/article/6123309"
	description = "references fake library - possible dynamic library hijacking"
  strings:
    $libnetresolv = "libnetresolv.so"
  condition:
    any of them
}

rule libs_fake : suspicious {
  meta:
    ref = "https://cert.gov.ua/article/6123309"
	description = "references fake library, possible dynamic library hijacking"
  strings:
    $libnetresolv = "libs.so" fullword
  condition:
    any of them
}


rule libc_fake_number : suspicious {
  meta:
    ref = "https://cert.gov.ua/article/6123309"
	description = "references a non-standard libc library (normally libc.so.6)"
  strings:
    $fake_libc_version = /libc.so.[2345789]/
  condition:
    any of them
}

rule hardcoded_usr_local_lib : suspicious {
  meta:
    ref = "https://www.cadosecurity.com/migo-a-redis-miner-with-novel-system-weakening-techniques/"
	description = "hardcodes /usr/local/lib path, possible dynamic library hijacking"
  strings:
    $ref = /\/usr\/local\/lib\/[\w\-\.]{0,32}.so/
  condition:
    any of them
}
