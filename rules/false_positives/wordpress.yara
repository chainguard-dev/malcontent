rule module_audio_video_quicktime: override {
  meta:
    description         = "module.audio-video.quicktime.php"
    bitwise_obfuscation = "medium"

  strings:
    $author             = "getID3() by James Heinrich <info@getid3.org>"
    $filename           = "module.audio-video.quicktime.php"
    $irregular_comments = /\/\/ (ALBum|ARTist|CaTeGory|CoMmenT|COMposer|CoPyRighT|COVeR|DESCription|GAPless|GENre|GRouPing|LYRics|PURchase|RaTiNG|SOrt|TRacK|ViDeo|WRiTer)/
    $repository         = "https://github.com/JamesHeinrich/getID3"
    $site               = "https://www.getid3.org"

  condition:
    filesize < 192KB and $author and $filename and $repository and $site and any of ($irregular*)
}
