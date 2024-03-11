rule sleep_rm_sh_pipe : suspicious {
  meta:
    ref = "https://cert.gov.ua/article/6123309"
    hash_2023_uacert_backpipe = "d7f012d3985cb0666de172e158e3d0e0b516e2fffd5da942e027fe437c8af1c7"
  strings:
    $s_sleep_time = /sleep \d{1,128}/
    $s_pipe_sh = "| /bin/sh"
    $s_rm_rf = "rm -rf"
  condition:
    all of them
}
