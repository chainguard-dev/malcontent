rule cxFreeze_Python_executable: high {
  meta:
    description = "uses cxFreeze packer"
    filetypes   = "py"

  strings:
    $cxfreeze      = "cx_Freeze"
    $not_importlib = "tool like cx_Freeze"

  condition:
    // "tool like cx_Freeze" contains $cxfreeze, so prose about the packer used
    // to silence a real cx_Freeze marker; require an occurrence the prose does
    // not account for.
    filesize < 10485760 and $cxfreeze and #cxfreeze > #not_importlib
}
