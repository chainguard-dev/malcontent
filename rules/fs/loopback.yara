rule dev_loopback: medium linux {
  meta:
    capability  = "CAP_SYS_RAWIO"
    description = "access virtual block devices (loopback)"

  strings:
    $val = /\/dev\/loop[\$%\w\{\}]{0,16}/

  condition:
    any of them
}
