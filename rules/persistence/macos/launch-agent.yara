
rule macos_LaunchAgents : notable {
	meta:
		description = "Persist via LaunchAgents"
		platforms = "darwin"
	strings:
		$ref = "LaunchAgents" fullword
	condition:
		any of them
}

rule macos_personal_launch_agent : notable {
  meta:
    hash_2011_bin_p_start = "490f96b3ce11827fe681e0e2bd71d622399f16c688e5fedef4f79089c7cf2856"
    hash_2017_Dockster = "8da09fec9262d8bbeb07c4e403d1da88c04393c8fc5db408e1a3a3d86dddc552"
    hash_2016_Eleanor_eleanr_script = "2c752b64069e9b078103adf8f5114281b7ce03f1ca7a995228f180140871999e"
    hash_2021_Gmera_Licatrade = "ad27ae075010795c04a6c5f1303531f3f2884962be4d741bf38ced0180710d06"
    hash_2018_CookieMiner_uploadminer = "6236f77899cea6c32baf0032319353bddfecaf088d20a4b45b855a320ba41e93"
  strings:
    $home = /\$HOME\/Library\/LaunchAgents[\.\/\w ]{0,32}/
    $tilde = /\~\/Library\/LaunchAgents[\.\/\w ]{0,32}/
    $not_apple_private = "com.apple.private"
    $not_git = "GIT_CONFIG"
    $not_apple_program = "@(#)PROGRAM:"
  condition:
    ($home or $tilde) and none of ($not*)
}
