<?php
//including files
$module_name = 'eam_packets_lib';
require_once("eam_min.php");
require_once("eam_pw_packets.php");

//setting config
$server_config = [
	'host' => '127.0.0.1',
	'port' => [
		'database' => 29400,
		'delivery' => 29100,
		'provider' => 29300,
		'glinkd1' => 29000,
	],
];
eam_packets_lib::setConfig($server_config);

//executing
try
{
	//check eam_pw_packets class if you want to add more packets
	$RoleData = eam_pw_packets::get_role_data(1024);
	var_dump($RoleData);
}
catch (eam_exception $Exc)
{
	var_dump($Exc);
}