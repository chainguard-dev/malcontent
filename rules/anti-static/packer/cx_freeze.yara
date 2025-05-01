rule cxFreeze_Python_executable: high {
  meta:
    description = "uses cxFreeze packer"
    filetypes   = "text/x-python"

  strings:
    $cxfreeze      = "cx_Freeze"
    $not_importlib = "tool like cx_Freeze"

  condition:
    filesize < 10485760 and $cxfreeze and none of ($not*)
}
