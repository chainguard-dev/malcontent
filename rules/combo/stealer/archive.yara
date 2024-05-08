
rule py_crypto_urllib_multiprocessing : suspicious {
  meta:
    deescription = "calls multiple functions useful for exfiltrating data"
    ref = "trojan.python/drop - e8eb4f2a73181711fc5439d0dc90059f54820fe07d9727cf5f2417c5cec6da0e"
    hash_2023_Downloads_e6b6 = "e6b6cf40d605fc7a5e8ba168a8a5d8699b0879e965d2b803e29b87926cba861f"
    hash_2023_Linux_Malware_Samples_4259 = "4259f2da90bf344092abc071f376753adaf077e13aeed684a7a3c2950ec82f69"
    hash_2023_Linux_Malware_Samples_7c5c = "7c5c84eb86a72395bf75510d5a1a51553a025668d6477dbef86ad12da7bc6b8a"
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
  meta:
    hash_2017_CoinThief = "7f32fdcaefee42f93590f9490ab735ac9dfeb22a951ff06d721145baf563d53b"
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
