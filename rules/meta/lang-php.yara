rule php {
  strings:
	$ref = "<?php"
  condition:
	all of them
}
