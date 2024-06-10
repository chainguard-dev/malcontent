rule RokRAT
{
meta:
	id = "67CbAcgxp3LrNC8G138xsq"
	fingerprint = "9a421d0257276c98d57abdaeb1e31e98956ec8ecf97d48827b35b527d174f35e"
	version = "1.0"
	modified = "2024-03-08"
	status = "RELEASED"
	sharing = "TLP:WHITE"
	source = "BARTBLAZE"
	author = "@bartblaze"
	description = "Identifies RokRAT."
	category = "MALWARE"
	malware_type = "RAT"
	reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rokrat"

strings:
	$new_pe = {0f b6 03 8d 4b 05 03 c8 89 4? ?? 8b 44 18 01 89 4? ?? 8d ?? 98 f4 ff ff 50 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8d ?? 98 f4 ff ff 4f 8a 
	4? ?? 47 84 c0 75 ?? 8b 5? ?? be ?? ?? ?? ?? 33 c0 8b c8 a5 a5 a5 a5 a4 8b 7? ?? 85 d2 74 ?? 8a 26 8a 04 31 32 c4 34 ?? 88 04 31 41 3b ca}

	$str_1 = "%s%04X%04X.tmp" ascii wide
	$str_2 = "360Tray.exe" ascii wide
	$str_3 = "dir /A /S %s >> \"%%temp%%/%c_.TMP\"" ascii wide
	$str_4 = "KB400928_doc.exe" ascii wide
	$str_5 = "\\%d.dat" ascii wide
	$str_6 = "%spid:%d,name:%s,path:%s%s" ascii wide
	$str_7 = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" ascii wide

	$comms_1 = "127.0.0.1" ascii wide
	$comms_2 = "api.pcloud.com" ascii wide
	$comms_3 = "my.pcloud.com" ascii wide
	$comms_4 = "cloud-api.yandex.net" ascii wide
	$comms_5 = "api.dropboxapi.com" ascii wide
	$comms_6 = "content.dropboxapi.com" ascii wide
	$comms_7 = "Content-Type: voice/mp3" ascii wide

condition:
	$new_pe or 
	4 of ($str_*) or 
	(6 of ($comms_*) and 2 of ($str_*))
}
