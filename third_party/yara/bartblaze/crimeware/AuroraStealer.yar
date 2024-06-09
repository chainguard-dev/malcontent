rule AuroraStealer
{
meta:
	id = "6Z1CVWsCBgJV6aRbfDFvlr"
	fingerprint = "06f893451d74f7cc924b9988443338ed9d86d8afb3b1facdfee040bce0c45289"
	version = "1.0"
	first_imported = "2023-05-26"
	last_modified = "2023-05-26"
	status = "RELEASED"
	sharing = "TLP:WHITE"
	source = "BARTBLAZE"
	author = "@bartblaze"
	description = "Identifies Aurora Stealer."
	category = "MALWARE"
	malware = "Aurora Stealer"
	reference = " https://malpedia.caad.fkie.fraunhofer.de/details/win.aurora_stealer"
  
strings:
	$ = "main.(*DATA_BLOB).ToByteArray" ascii wide
	$ = "main.base64Decode" ascii wide
	$ = "main.base64Encode" ascii wide
	$ = "main.Capture" ascii wide
	$ = "main.CaptureRect" ascii wide
	$ = "main.compresss" ascii wide
	$ = "main.ConnectToServer" ascii wide
	$ = "main.countupMonitorCallback" ascii wide
	$ = "main.CreateImage" ascii wide
	$ = "main.enumDisplayMonitors" ascii wide
	$ = "main.FileExsist" ascii wide
	$ = "main.getCPU" ascii wide
	$ = "main.getDesktopWindow" ascii wide
	$ = "main.GetDisplayBounds" ascii wide
	$ = "main.getGPU" ascii wide
	$ = "main.GetInfoUser" ascii wide
	$ = "main.getMasterKey" ascii wide
	$ = "main.getMonitorBoundsCallback" ascii wide
	$ = "main.getMonitorRealSize" ascii wide
	$ = "main.GetOS" ascii wide
	$ = "main.Grab" ascii wide
	$ = "main.MachineID" ascii wide
	$ = "main.NewBlob" ascii wide
	$ = "main.NumActiveDisplays" ascii wide
	$ = "main.PathTrans" ascii wide
	$ = "main.RandStringBytes" ascii wide
	$ = "main.SendToServer_NEW" ascii wide
	$ = "main.SetUsermame" ascii wide
	$ = "main.sysTotalMemory" ascii wide
	$ = "main.xDecrypt" ascii wide
	$ = "main.Zip" ascii wide
	$ = "type..eq.main.Browser_G" ascii wide
	$ = "type..eq.main.Crypto_G" ascii wide
	$ = "type..eq.main.DATA_BLOB" ascii wide
	$ = "type..eq.main.FileGrabber_G" ascii wide
	$ = "type..eq.main.FTP_G" ascii wide
	$ = "type..eq.main.Grabber" ascii wide
	$ = "type..eq.main.ScreenShot_G" ascii wide
	$ = "type..eq.main.Steam_G" ascii wide
	$ = "type..eq.main.STRUSER" ascii wide
	$ = "type..eq.main.Telegram_G" ascii wide
	
condition:
	25 of them
}
