
rule chmod_executable_plus : notable {
  meta:
    description = "makes file executable"
  strings:
    $val = /chmod [\-\w ]{0,4}\+[rw]{0,2}x[ \$\@\w\/\.]{0,64}/
  condition:
    $val
}

rule chmod_executable_octal : suspicious {
  meta:
    description = "makes file executable"
    hash_2023_Unix_Downloader_Rocke_228e = "228ec858509a928b21e88d582cb5cfaabc03f72d30f2179ef6fb232b6abdce97"
    hash_2023_Unix_Downloader_Rocke_2f64 = "2f642efdf56b30c1909c44a65ec559e1643858aaea9d5f18926ee208ec6625ed"
    hash_2023_Unix_Downloader_Rocke_6107 = "61075056b46d001e2e08f7e5de3fb9bfa2aabf8fb948c41c62666fd4fab1040f"
  strings:
    $val = /chmod [\-\w ]{0,4}\+[rw]{0,2}[75][ \$\@\w\/\.]{0,64}/
  condition:
    $val
}

rule chmod_executable_ruby : suspicious {
  meta:
    jumpcloud = "https://www.mandiant.com/resources/blog/north-korea-supply-chain"
  strings:
    $chmod_7_val = /File\.chmod\(\d{0,16}7\d{0,16}/
  condition:
    any of them
}
