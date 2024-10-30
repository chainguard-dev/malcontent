rule powershell_js: override windows {
  meta:
    casing_obfuscation = "medium"
    description        = "powershell.js"

  strings:
    $const           = "const"
    $export          = "module.exports = powershell;"
    $powershell_func = /function powershell(\S{4})/
    $verbs           = "// https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands"

  condition:
    all of them
}
