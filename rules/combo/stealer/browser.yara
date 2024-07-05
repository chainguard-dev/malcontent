
rule multiple_browser_credentials : high {
  meta:
    hash_2023_Downloads_016a = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2023_Downloads_589d = "589dbb3f678511825c310447b6aece312a4471394b3bc40dde6c75623fc108c0"
    hash_2023_Downloads_Brawl_Earth = "fe3ac61c701945f833f218c98b18dca704e83df2cf1a8994603d929f25d1cce2"
  strings:
    $c_library_keychains = "/Library/Keychains"
    $c_cookies_sqlite = "cookies.sqlite"
    $c_moz_cookies = "moz_cookies"
    $c_opera_gx = "OperaGX"
    $c_keychain_db = "login.keychain-db"
    $c_dscl_local = "dscl /Local/Default"
    $c_osascript = "osascript"
    $c_find_generic_password = "find-generic-password"
    $not_security = "PROGRAM:security"
    $not_verbose = "system_verbose"
    $not_kandji = "com.kandji.profile.mdmprofile"
    $not_xul = "XUL_APP_FILE"
  condition:
    3 of ($c_*) and none of ($not_*)
}

rule multiple_browser_refs : critical {
  meta:
	description = "Makes references to multiple browser credentials"
  strings:
    $fs_config = ".config" fullword
    $fs_app_support = "Application Support"
    $fs_app_support_slash = "Application\\ Support"
    $fs_chrome = "Google/Chrome"
    $fs_chrome_local_state = "Chrome/Local State"
    $fs_chrome_userdata = "Chrome/User Data"
    $fs_cookies = "Cookies"
    $fs_cookies_sqlite = "cookies.sqlite"
	$fs_firefox = "Mozilla/Firefox"
    $fs_firefox_profiles = "Firefox/Profiles"
    $fs_form_history = "formhistory.sqlite"
    $fs_moz_cookies = "moz_cookies"
    $fs_places_sqlite = "places.sqlite"
	$fs_roaming = "Roaming/"
	$fs_user_data = "User Data"

	$name_brave = "Brave-Browser"
    $name_brave_software = "BraveSoftware"
    $name_chrome = "Google Chrome"
    $name_opera_gx = "OperaGX"
	$name_firefox = "Firefox"
	$name_opera_gx_dir = "Opera GX"
    $name_opera = "Opera Software"
	$name_yandex = "YandexBrowser"
  condition:
	2 of ($name*) and 3 of ($fs*)
}

rule userdata_browser_archiver : medium {
  meta:
    description = "Uses HTTP, archives, and references multiple browsers"
    hash_2023_Downloads_016a = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2024_Downloads_3105 = "31054fb826b57c362cc0f0dbc8af15b22c029c6b9abeeee9ba8d752f3ee17d7d"
    hash_2023_Downloads_589d = "589dbb3f678511825c310447b6aece312a4471394b3bc40dde6c75623fc108c0"
  strings:
    $d_config = ".config" fullword
    $d_app_support = "Application Support" fullword
	$d_state = "User Data" fullword
    $h_http = "http" fullword
	$h_https = "https" fullword
    $h_POST = "POST" fullword
	$h_discord = "Discord" fullword
    $z_zip = "zip" fullword
    $z_ZIP = "ZIP" fullword
    $z_ditto = "ditto" fullword
    $z_tar = "tar" fullword
	$z_store = "assasans/storage" fullword
    $b_Yandex = "Yandex"
    $b_Brave = "Brave"
    $b_Firefox = "Firefox"
    $b_Safari = "Safari"
    $b_Chrome = "Chrome"
  condition:
    any of ($d*) and any of ($h*) and any of ($z*) and 2 of ($b*)
}
