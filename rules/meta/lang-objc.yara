rule _OBJC_ {
  strings:
    $zprefix = "_OBJC_"

  condition:
    #zprefix > 3
}
