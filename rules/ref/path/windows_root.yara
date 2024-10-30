rule windows_path: windows {
  meta:
    description = "path reference for C:\\Windows (may be partial)"

  strings:
    $forward = /C:\/wi[ndowst]{0,5}/ nocase
    $back    = /C:\\wi[ndowst]{0,5}/ nocase

  condition:
    any of them
}
