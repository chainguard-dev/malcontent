rule relative_hidden_launcher: medium {
  strings:
    $relative_hidden = /\.\/\.[\w][\w\/\.\_\-]{3,16}/ fullword
    $x_exec          = "exec"
    $x_bash          = "bash"
    $x_system        = "system"
    $x_popen         = "popen"
    $not_vscode      = "vscode"
    $not_test        = "./.test"
    $not_prove       = ".proverc"
    $not_private     = "/System/Library/PrivateFrameworks"

  condition:
    $relative_hidden and any of ($x*) and none of ($not*)
}
