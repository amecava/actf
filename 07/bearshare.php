<?php
include_once 'config.php';
$nonce = md5(rand(10000000, 99999999).rand(10000000, 99999999));

function gen_hash($n, $sv){
	$first = hash_hmac('sha256',$n,$S_KEY);
	return hash_hmac('sha256',$sv,$first);
}

function validate_hash(){
	if(empty($_POST['hash']) || empty($_POST['storagesv'])){
		die('Cannot verify server');
	}
	if(isset($_POST['nonce'])){
		$S_KEY = hash_hmac('sha256',$_POST['nonce'],$S_KEY);

	}
	$final_hash = hash_hmac('sha256',$_POST['storagesv'],$S_KEY);
	if ($final_hash !== $_POST['hash']){
		die('Cannot verify server');
	}

}

function filter($x){
	$x = (string)$x;
	if(preg_match('/http|https|\@|\s|:|\/\//mi',$x)){
		return false;

	}
	return $x;

}


if(isset($_POST['messid'])){

	$messid = $_POST['messid'];
	validate_hash();
	$url="";
	if($_POST['storagesv'] === 'message1.local' or $_POST['storagesv'] === 'message2.local'){
		$url = 'http://'.$_POST['storagesv'].'/';

	} elseif ($_POST['storagesv']==="gimmeflag") {
		die('flag{*******}'); //flag censored for security reasons :)

	}

	$messid = filter($messid);

	if($messid){
		$url .= $messid;
		die('Messages not yet implemented')	

	} else {
		die('Hey, are you a haxor?');

	}

}

?>