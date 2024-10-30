rule go {
  strings:
    $buildinfo = "go:buildinfo"
    $gostring  = "_runtime.gostring"
    $buildid   = "go.buildid"

  condition:
    any of them
}
