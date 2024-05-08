
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

rule multiple_browser_credentials_2 {
  strings:
    $a_google_chrome = "Google/Chrome"
    $a_app_support = "Application Support"
    $a_app_support_slash = "Application\\ Support"
    $a_cookies_sqlite = "cookies.sqlite"
    $a_cookies = "Cookies"
    $a_places_sqlite = "places.sqlite"
    $a_moz_cookies = "moz_cookies"
    $a_firefox_profiles = "Firefox/Profiles"
    $a_opera_gx = "OperaGX"
    $a_form_history = "formhistory.sqlite"
    $a_chrome_local_state = "Chrome/Local State"
    $a_brave_software = "BraveSoftware"
    $a_opera = "Opera Software"
  condition:
    4 of ($a_*)
}

rule multiple_browser_refs : medium {
  meta:
    description = "Uses HTTP, archives, and references multiple browsers"
    hash_2023_Downloads_016a = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2024_Downloads_3105 = "31054fb826b57c362cc0f0dbc8af15b22c029c6b9abeeee9ba8d752f3ee17d7d"
    hash_2023_Downloads_589d = "589dbb3f678511825c310447b6aece312a4471394b3bc40dde6c75623fc108c0"
  strings:
    $d_config = ".config" fullword
    $d_app_support = "Application Support" fullword
    $h_http = "http" fullword
    $h_POST = "POST" fullword
    $z_zip = "zip" fullword
    $z_ZIP = "ZIP" fullword
    $z_ditto = "ditto" fullword
    $z_tar = "tar" fullword
    $b_Yandex = "Yandex"
    $b_Brave = "Brave"
    $b_Firefox = "Firefox"
    $b_Safari = "Safari"
    $b_Chrome = "Chrome"
  condition:
    any of ($d*) and any of ($h*) and any of ($z*) and 2 of ($b*)
}
