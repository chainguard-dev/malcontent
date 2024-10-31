rule win_defender_configure: high {
  meta:
    description = "Uses powershell to configure Windows Defender"
  strings:
	$exclusion = /[\w \'\:\\\"\-]{0,32}Add-MpPreference[\w \'\:\\\"\-]/
  condition:
	$exclusion
}

rule win_defender_exclusion: critical {
  meta:
    description = "Uses powershell to define Windows Defender exclusions"
  strings:
	$exclusion = /[\w \'\:\\\"\-]{0,32}Add-MpPreference.{0,32}Exclusion[\w \'\:\\\"]{0,32}/
  condition:
	$exclusion
}