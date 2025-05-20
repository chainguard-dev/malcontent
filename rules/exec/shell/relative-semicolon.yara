include "rules/global/global.yara"

rule semicolon_relative_path_cd: medium {
  meta:
    ref = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"

  strings:
    $semi_relative = /[\/\w]{3,};[ +]{0,8}\.\/\.{0,8}\w{3,}/

  condition:
    any of them
}

rule semicolon_relative_path_high: high {
  meta:
    ref = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"

  strings:
    $semi_relative = /[\/\w]{3,};[ +]{0,8}\.\/\.{0,8}\w{3,}/

  condition:
    any of them and not global_local_cd
}
