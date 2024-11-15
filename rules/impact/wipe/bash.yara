rule sleep_rm_sh_pipe: high {
  meta:
    ref = "https://cert.gov.ua/article/6123309"

  strings:
    $s_sleep_time = /sleep \d{1,128}/
    $s_pipe_sh    = "| /bin/sh"
    $s_rm_rf      = "rm -rf"

  condition:
    filesize < 16KB and all of them
}

