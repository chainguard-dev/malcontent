rule nodejs {
  strings:
	$ref = "bin/env node"
	$ref2 = "import {"
	$ref3 = " } from '"
  condition:
	any of them
}
