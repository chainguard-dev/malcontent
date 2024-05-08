
rule exotic_email_addr : medium {
  meta:
    description = "Contains an exotic email address"
    hash_2023_grandmask_3_13_setup = "8835778f9e75e6493693fc6163477ec94aba723c091393a30d7e7b9eed4f5a54"
    hash_2023_py_guigrand_4_67_setup = "4cb4b9fcce78237f0ef025d1ffda8ca8bc79bf8d4c199e4bfc6eff84ce9ce554"
    hash_2023_py_killtoolad_3_65_setup = "64ec7b05442356293e903afe028637d821bad4444c4e1e11b73a4ff540fe480b"
  strings:
    $e_re = /[\w\.\-]{1,32}@(proton|tuta|mailfence|onion|gmx)[\w\.\-]{1,64}/
  condition:
    any of ($e*)
}
