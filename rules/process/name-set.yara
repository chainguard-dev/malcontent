rule __progname : notable {
	meta:
		description = "get or set the programs name"
		ref = "https://stackoverflow.com/questions/273691/using-progname-instead-of-argv0"
	strings:
		$ref = "__progname"
	condition:
		any of them
}

rule bash_sets_name_val : notable {
  meta:
	description = "sets process name"
	ref = "https://www.jamf.com/blog/cryptojacking-macos-malware-discovered-by-jamf-threat-labs/"
  strings:
	$ref = /exec -a[ \"\$\{\}\@\w\/\.]{0,64}/
  condition:
	any of them
}