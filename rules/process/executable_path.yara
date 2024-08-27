rule python_sys_executable : medium {
  meta:
    description = "gets executable associated to this process"
  strings:
    $ref = "sys.executable" fullword
  condition:
    any of them
}
