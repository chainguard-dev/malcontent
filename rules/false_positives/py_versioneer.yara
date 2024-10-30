rule versioneer_py: override {
  meta:
    description             = "versioneer.py"
    python_exec_near_enough = "medium"

  strings:
    $script     = "versioneer.py"
    $versioneer = "VERSIONEER"

  condition:
    filesize < 200KB and all of them
}
