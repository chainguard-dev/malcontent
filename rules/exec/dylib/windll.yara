rule windll_user: medium windows {
  meta:
    description = "executes code from Windows dynamic libraries"

  strings:
    $ctypes = "ctypes"
    $windll = /windll\.[\w\.]{4,64}/

  condition:
    all of them
}
