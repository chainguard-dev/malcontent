
rule dev_loopback : notable {
  meta:
    capability = "CAP_SYS_RAWIO"
    description = "access virtual block devices (loopback)"
    hash_2023_usr_adxintrin_b = "a51a4ddcd092b102af94139252c898d7c1c48f322bae181bd99499a79c12c500"
  strings:
    $val = /\/dev\/loop[\$%\w\{\}]{0,16}/
  condition:
    any of them
}
