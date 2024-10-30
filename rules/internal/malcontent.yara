rule malcontent: harmless {
  meta:
    __malcontent__ = "true"
    description    = "match the malcontent binary (mal) and omit it unless --ignore-self=false"

  strings:
    $b_behavior   = "malcontent.Behavior"
    $f_action     = "malcontent/pkg/action"
    $f_malcontnet = "malcontent/pkg/malcontent"
    $f_compile    = "malcontent/pkg/compile"
    $f_profile    = "malcontent/pkg/profile"
    $f_render     = "malcontent/pkg/render"
    $f_report     = "malcontent/pkg/report"
    $f_version    = "malcontent/pkg/version"

  condition:
    3 of them
}
