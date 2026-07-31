rule relative_hidden_launcher: medium {
  strings:
    $relative_hidden = /\.\/\.[\w][\w\/\.\_\-]{3,16}/ fullword
    $x_exec          = "exec"
    $x_bash          = "bash"
    $x_system        = "system"
    $x_popen         = "popen"
    $not_vscode      = "vscode"
    $not_private     = "/System/Library/PrivateFrameworks"

    // $relative_hidden matches each of these verbatim, so their presence used to
    // excuse every other relative hidden launcher in the file. They are counted
    // instead: fire only on a $relative_hidden match none of them accounts for.
    // ".proverc" is spelled with its "./" so it lines up with $relative_hidden,
    // and "\./.source" is a minified-JS regex literal followed by its .source
    // property (Prism grammars), which reads as a relative hidden path.
    $notsub_test      = "./.test"
    $notsub_prove     = "./.proverc"
    $notsub_js_source = "\\./.source"

  condition:
    $relative_hidden and any of ($x*) and none of ($not_*) and #relative_hidden > #notsub_test + #notsub_prove + #notsub_js_source
}
