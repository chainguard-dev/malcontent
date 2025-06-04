rule win_defender_configure: high {
  meta:
    description = "Uses powershell to configure Windows Defender"

  strings:
    $exclusion = /[\w \'\:\\\"\-]{0,32}Add-MpPreference[\w \'\:\\\"\-]/

    // https://help.eclipse.org/latest/nftopic/org.eclipse.platform.doc.isv/reference/api/org/eclipse/ui/internal/WindowsDefenderConfigurator.html
    $not_configurator1 = "WindowsDefenderConfigurator_"
    $not_configurator2 = "org/eclipse/ui/internal/WindowsDefenderConfigurator"

  condition:
    $exclusion and none of ($not*)
}

rule win_defender_exclusion: critical {
  meta:
    description = "Uses powershell to define Windows Defender exclusions"

  strings:
    $exclusion = /[\w \'\:\\\"\-]{0,32}Add-MpPreference.{0,32}Exclusion[\w \'\:\\\"]{0,32}/

    // https://help.eclipse.org/latest/nftopic/org.eclipse.platform.doc.isv/reference/api/org/eclipse/ui/internal/WindowsDefenderConfigurator.html
    $not_configurator1 = "WindowsDefenderConfigurator_"
    $not_configurator2 = "org/eclipse/ui/internal/WindowsDefenderConfigurator"

  condition:
    $exclusion and none of ($not*)
}
