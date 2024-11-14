rule exotic_email_addr: medium {
  meta:
    description                    = "Contains an exotic email address"
    hash_2023_grandmask_3_13_setup = "8835778f9e75e6493693fc6163477ec94aba723c091393a30d7e7b9eed4f5a54"

  strings:
    $e_re = /[\w\.\-]{1,32}@(proton|tuta|mailfence|onion|gmx)[\w\.\-]{1,64}/

  condition:
    any of ($e*)
}
