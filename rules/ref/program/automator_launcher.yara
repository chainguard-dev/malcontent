rule automator_launcher {
  meta:
    hash_2018_MacOS_Application_Stub = "51678e33f687bea9f4930599c5483a1b0dba74dc9511a740855a20abe07bcfdb"
  strings:
    $automator = "/System/Library/CoreServices/Automator Launcher.app"
    $applet = "com.apple.automator.applet"
  condition:
    filesize < 2097152 and all of them
}