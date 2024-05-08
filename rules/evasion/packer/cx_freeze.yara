
rule cxFreeze_Python_executable : suspicious {
  meta:
    hash_2023_MacStealer_weed = "6a4f8b65a568a779801b72bce215036bea298e2c08ec54906bb3ebbe5c16c712"
  strings:
    $cxfreeze = "cx_Freeze"
  condition:
    filesize < 10485760 and $cxfreeze
}
