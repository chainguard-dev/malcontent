rule test_windows: override {
  meta:
    description                                    = "test_windows.py"
    SIGNATURE_BASE_Powershell_Susp_Parameter_Combo = "low"

  strings:
    $cext     = "cext = psutil._psplatform.cext"
    $class    = "class WindowsTestCase(PsutilTestCase)"
    $comment1 = "\"\"\"Windows specific tests.\"\"\""
    $comment2 = "\"\"\"Currently not used, but available just in case. Usage:"
    $comment3 = ">>> powershell("
    $comment4 = "Get-CIMInstance Win32_PageFileUsage | Select AllocatedBaseSize\")"
    $import   = "import psutil"

  condition:
    filesize < 40KB and all of them
}
