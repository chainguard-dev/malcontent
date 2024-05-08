
rule py_crypto_urllib_multiprocessing : suspicious {
  meta:
    deescription = "calls multiple functions useful for exfiltrating data"
    ref = "trojan.python/drop - e8eb4f2a73181711fc5439d0dc90059f54820fe07d9727cf5f2417c5cec6da0e"
  strings:
    $f_subprocess = "subprocess"
    $f_tarfile = "tarfile"
    $f_urllib = "urllib"
    $f_zipfile = "zipfile"
    $f_blake2 = "blake2"
    $f_glob = "glob"
    $f_libcrypto = "libcrypto"
    $not_capa = "capa.engine"
  condition:
    80% of ($f*) and none of ($not*)
}

rule open_and_archive : suspicious {
  strings:
    $open = "/usr/bin/open" fullword
    $defaults = "/usr/bin/defaults"
    $tar = "/usr/bin/tar"
    $zip = "/usr/bin/zip"
    $not_private = "/System/Library/PrivateFrameworks/"
    $not_keystone = "Keystone"
    $not_sparkle = "org.sparkle-project.Sparkle"
    $hashbang = "#!"
  condition:
    ($open or $defaults) and ($tar or $zip) and none of ($not*) and not $hashbang at 0
}
