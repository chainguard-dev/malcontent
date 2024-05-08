
rule expect_spawn : suspicious {
  meta:
    ref = "https://cert.gov.ua/article/6123309"
    hash_2023_uacert_socket = "9ca4a18bce328b79720fd18bee56f1f4778f492c70f14dd0d3fdf2148c3e3998"
  strings:
    $expect = "expect -"
    $s_cron = "spawn su"
    $s_password = "password"
    $s_whoami = "whoami"
  condition:
    $expect and any of ($s*)
}
