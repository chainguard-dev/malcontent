rule npm_dropper : critical {
  meta:
	description = "NPM binary dropper"
    ref = "https://www.reversinglabs.com/blog/a-lurking-npm-package-makes-the-case-for-open-source-health-checks"
  strings:
	$npm_format = /"format":/
	$npm_lint = /"lint":/
	$npm_postversion = /"postversion":/
	$npm_postinstall = /"postinstall":/

	$fetch = /"(curl|wget) /
	
    $url = /https{0,1}:\/\/[\w][\w\.\/\-_\?=\@]{8,64}/


	$chmod = "chmod"
  condition:
	filesize <16KB and 2 of ($npm*) and $fetch and $url and $chmod
}
