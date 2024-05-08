
rule cxFreeze_Python_executable : suspicious {
  strings:
    $cxfreeze = "cx_Freeze"
  condition:
    filesize < 10485760 and $cxfreeze
}
