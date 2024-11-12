rule ExecShellScript: medium {
  meta:
    description = "Create a Windows Scripting Host (WSH) object"

  strings:
    $ExecShell = "WScript.CreateObject(\"WScript.Shell\")"

  condition:
    any of them
}
