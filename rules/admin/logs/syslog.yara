
rule var_log_syslog : suspicious {
  meta:
    description = "accesses system logs"
    hash_2023_init_d_abrt_oops = "192b763638d0be61c4ba45e08f86df22318ab741297d6841d1009cca9bddad30"
    hash_2023_usr_adxintrin_b = "a51a4ddcd092b102af94139252c898d7c1c48f322bae181bd99499a79c12c500"
    hash_2023_Unix_Downloader_Rocke_228e = "228ec858509a928b21e88d582cb5cfaabc03f72d30f2179ef6fb232b6abdce97"
  strings:
    $ref = "/var/log/messages" fullword
    $ref2 = "/var/log/syslog" fullword
  condition:
    any of them
}
