rule open_and_archive : suspicious {
  meta:
    hash_2014_CoinThief = "7f32fdcaefee42f93590f9490ab735ac9dfeb22a951ff06d721145baf563d53b"
  strings:
    $open = "/usr/bin/open" fullword
    $defaults = "/usr/bin/defaults"
    $tar = "/usr/bin/tar"
    $zip = "/usr/bin/zip"
    $not_private = "/System/Library/PrivateFrameworks/"
	$not_keystone = "Keystone"
    $not_sparkle = "org.sparkle-project.Sparkle"
	$hashbang = "#!"
  condition:
    ($open or $defaults) and ($tar or $zip) and none of ($not*) and not $hashbang at 0
}
