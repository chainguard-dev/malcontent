rule DragonOK_CHWRITER_strings {
    meta:
      description = "CHWRITER malware"
      author = "JPCERT/CC Incident Response Group"
      hash = "fb1ee331be22267bc74db1c42ebb8eb8029c87f6d7a74993127db5d7ffdceaf4"

  	strings:
      $command="%s a a b c %d \"%s\"" wide

	  condition:
    	$command
}

rule DragonOK_sysget_strings {
    meta:
      description = "sysget malware"
      author = "JPCERT/CC Incident Response Group"
      hash = "a9a63b182674252efe32534d04f0361755e9f2f5d82b086b7999a313bd671348"

  	strings:
      $netbridge = "\\netbridge" wide
      $post = "POST" wide
      $cmd = "cmd /c " wide
      $register = "index.php?type=register&pageinfo" wide

    condition:
    	($netbridge and $post and $cmd) or $register
}
