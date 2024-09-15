
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
    hash_1985_actions_UserGet = "e3a457ec75e3a042fb34fa6d49e0e833265d21d26c4e0119aaa1b6ec8a9460ec"
    hash_1985_build_stealer = "d49043306ff8d6b394c6f39d70bd208ad740a6030d3cc5b5427d03cc7e494e7f"
    hash_1985_src_stealer = "9af37b5973ee1e683d9708591cbe31b8a1044aab88b92b5883bdd74bcf8d807b"
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
    $name_brave_software = "BraveSoftw"
    $name_chrome = "Google Chrome"
    $name_opera_gx = "Opera"
    $name_firefox = "Firefox"
    $name_opera = "Opera Software"
    $name_yandex = "YandexBrowser"

    $not_chromium = "ChromiumBrowser"
    $not_chromium_comment = "When this is enabled, Chromium can use"
    $not_chromium_issues = "https://issues.chromium.org/"
    $not_google = "developed by Google"
    $not_google_chrome_software = "The Google Chrome software"
    $not_bugzilla = "https://bugzilla.mozilla.org"
    $not_ff_js = "Firefox can even throw an error"
    $not_generated_comment = "// This file is generated"
    $not_generated_file = "/utils/generate_types/index.js"
  condition:
    2 of ($name*) and 3 of ($fs*) and none of ($not*)
}

rule userdata_browser_archiver : high {
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
	$b_moz = "Roaming/Moz"
	$b_Opera = "Opera"

    $not_chromium = "ChromiumBrowser"
    $not_chromium_comment = "When this is enabled, Chromium can use"
    $not_chromium_issues = "https://issues.chromium.org/"
    $not_google = "developed by Google"
    $not_google_chrome_software = "The Google Chrome software"
    $not_bugzilla = "https://bugzilla.mozilla.org"
    $not_ff_js = "Firefox can even throw an error"
    $not_generated_comment = "// This file is generated"
    $not_generated_file = "/utils/generate_types/index.js"
  condition:
    any of ($d*) and any of ($h*) and any of ($z*) and 3 of ($b*) and none of ($not*)
}

rule smaller_userdata_browser_archiver : high {
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
	$b_moz = "Roaming/Moz"
	$b_Opera = "Opera"

    $not_chromium = "ChromiumBrowser"
    $not_chromium_comment = "When this is enabled, Chromium can use"
    $not_chromium_issues = "https://issues.chromium.org/"
    $not_google = "developed by Google"
    $not_google_chrome_software = "The Google Chrome software"
    $not_bugzilla = "https://bugzilla.mozilla.org"
    $not_ff_js = "Firefox can even throw an error"
    $not_generated_comment = "// This file is generated"
    $not_generated_file = "/utils/generate_types/index.js"
  condition:
    filesize < 64KB and any of ($d*) and any of ($h*) and any of ($z*) and 3 of ($b*) and none of ($not*)
}


rule chrome_encrypted_cookies : critical {
	meta:
		description = "Reads encrypted values from Chrome cookie store"
	strings:
		$select = /SELECT.{0,64}encrypted_value{0,64}cookies/
	condition:
		$select
}