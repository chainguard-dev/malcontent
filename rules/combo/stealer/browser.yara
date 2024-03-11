rule multiple_browser_credentials : suspicious {
  meta:
    hash_2023_stealer_hashbreaker = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2023_amos_stealer_e = "589dbb3f678511825c310447b6aece312a4471394b3bc40dde6c75623fc108c0"
    hash_2023_amos_stealer_a = "e6b6cf40d605fc7a5e8ba168a8a5d8699b0879e965d2b803e29b87926cba861f"
    hash_2018_CookieMiner_uploadminer = "6236f77899cea6c32baf0032319353bddfecaf088d20a4b45b855a320ba41e93"
    hash_2023_brawl_earth = "fe3ac61c701945f833f218c98b18dca704e83df2cf1a8994603d929f25d1cce2"
    hash_2023_Downloads_Chrome_Update = "eed1859b90b8832281786b74dc428a01dbf226ad24b182d09650c6e7895007ea"
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
  meta:
    hash_2023_brawl_earth = "fe3ac61c701945f833f218c98b18dca704e83df2cf1a8994603d929f25d1cce2"
    hash_2023_stealer_hashbreaker = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2023_amos_stealer_e = "589dbb3f678511825c310447b6aece312a4471394b3bc40dde6c75623fc108c0"
    hash_2023_amos_stealer_a = "e6b6cf40d605fc7a5e8ba168a8a5d8699b0879e965d2b803e29b87926cba861f"
    hash_2016_Calisto = "81c127c3cceaf44df10bb3ceb20ce1774f6a9ead0db4bd991abf39db828661cc"
    hash_2018_CookieMiner_uploadminer = "6236f77899cea6c32baf0032319353bddfecaf088d20a4b45b855a320ba41e93"
    hash_2017_GoPhoto = "a4d8367dc2df3a8539b9baf8ee48d09f5a8e9f9d2d58431909de0bb0816464a0"
    hash_2023_Downloads_Chrome_Update = "eed1859b90b8832281786b74dc428a01dbf226ad24b182d09650c6e7895007ea"
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
    $not_osquery = "OSQUERY_WORKER"
    $not_private = "/System/Library/PrivateFrameworks/"
  condition:
    3 of ($a_*) and none of ($not_*)
}

