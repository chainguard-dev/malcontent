rule expect_spawn: high {
  meta:
    ref = "https://cert.gov.ua/article/6123309"

  strings:
    $expect     = "expect -"
    $s_cron     = "spawn su"
    $s_password = "password"
    $s_whoami   = "whoami"

  condition:
    $expect and any of ($s*)
}
