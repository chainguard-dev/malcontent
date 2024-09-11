rule py_exe_stealer : critical {
  meta:
	description = "Compiled Python Windows Stealer"
  strings:
	$installer = "PyInstaller"
	$sqlite3 = "sqlite3"
	$l_cryptography = "cryptography"
	$l_requests = "requests.__version__"
	$l_socket = "socket"
	$l_subprocess = "subprocess"
	$l_win32 = "win32com"
	$l_xml = "xml.parsers.expat"
	$l_zipfile = "zipfile"
	$l_tarfile = "tarfile"
	$l_tempfile = "tempfile"
	$l_ciper = "Crypto\\Cipher"
  condition:
	filesize < 25MB and $installer and $sqlite3 and 90% of ($l*)
}
