<?php
class eam_packets_exception extends eam_exception {}
	class eam_pack_exception extends eam_packets_exception {}
	class eam_socket_exception extends eam_packets_exception {}
	class eam_pw_packets_exception extends eam_packets_exception {}

class eam_packets_lib extends eam_module
{
	protected static $event_codes = [
		//eam packets lib codes: 2 01 ?? [00-99] =============================================================================================================================
		//eam_packets_exception()
		20104 => [
			'event_info' => 'eam_packets_lib: !isset(config[var])',
		],
		//eam_pack_exception($code)
		20101 => [
			'event_info' => 'eam_packets_lib: f un_*: unpack length',
		],
		20102 => [
			'event_info' => 'eam_packets_lib: f un_struct: unpack structure',
		],
		20103 => [
			'event_info' => 'eam_packets_lib: f p_struct: pack structure',
		],
		//eam_socket_exception($code)
		20105 => [
			'event_info' => 'eam_packets_lib: f PW_send: socket error',
		],
		20106 => [
			'event_info' => 'eam_packets_lib: f PW_send: send problem',
		],
		20107 => [
			'event_info' => 'eam_packets_lib: f PW_send: recieve problem',
		],
		//eam_pw_packets_exception($code)
		20108 => [
			'event_info' => 'eam_packets_lib: response unpacking did not finished',
		],
		20109 => [
			'event_info' => 'eam_packets_lib: retcodes check failed',
		],
	];
	
	protected static $config = [
		'host' => '127.0.0.1',
		'port' => [
			'database' => 29400,
			'delivery' => 29100,
			'provider' => 29300,
			'glinkd1' => 29000,
		],
	];
	
	public static function setConfig(array $new_config)
	{
		self::$config = $new_config;
	}
	
	//p_*	: pack functions, returns value
	//un_*	: unpack fucntions, returns value (throws exceptions on fail)
	
	//=== cuint === ======================================================================================================================================================
	/*
		cuint(32) structure:
		lenght(1/2/3 bits) + data
		
		data:		 <= 7f		(0111 1111) 7 bits value mask
		result:		data(c)		
		
		data:			<= 3fff		(00 11 1111 1111 1111) 14 bits value mask
		result: 	8000 | data(n)	(10|00 0000 0000 0000) length
		
		data:			<= 1fffffff		(000 1 1111 1111 1111 1111 1111 1111 1111) 29 bits value mask
		result:		c0000000 | data(N)	(110|0 0000 0000 0000 0000 0000 0000 0000) length
		
		data:			<= ffffffff						(1111 1111 1111 1111 1111 1111 1111 1111) 32 bits value mask
		result:			E0.data(N)			(1110 0000 . 0000 0000 0000 0000 0000 0000 0000 0000) length
		
		data: > ffffffff
		result: not int32
	*/
	public static function p_cuint($value)
	{
		if ($value <= 0x7F)
			return pack("C", $value);
		else if ($value <= 0x3FFF)
			return pack("n", ($value | 0x8000));
		else if ($value <= 0x1FFFFFFF)
			return pack("N", ($value | 0xC0000000));
		else
			return pack("C", 0xE0).pack("N", $value);
	}
	
	//@throws eam_pack_exception(20101)
	public static function un_cuint($packed_data, &$offset)
	{
		$output = @unpack("C", substr($packed_data, $offset, 1));
		if ($output === false)
			throw new eam_pack_exception(20101);
		
		$offset++;
		switch($output[1] & 0xE0)
		{
			case 0xE0:
				$output = @unpack("N", substr($packed_data, $offset, 4));
				if ($output === false)
					throw new eam_pack_exception(20101);
				
				$offset += 4;
				break;
			case 0xC0:
				$output = @unpack("N", substr($packed_data, $offset - 1, 4));
				if ($output === false)
					throw new eam_pack_exception(20101);
				
				$output[1] &= 0x1FFFFFFF;
				$offset += 3;
				break;
			case 0x80:
			case 0xA0:
				$output = @unpack("n", substr($packed_data, $offset - 1, 2));
				if ($output === false)
					throw new eam_pack_exception(20101);
				
				$output[1] &= 0x3FFF;
				$offset++;
				break;
		}
		return $output[1];
	}
	
	//=== string === ==========================================================================================================================================================
	public static function p_string($value, $to = "UTF-16LE", $from = "UTF-8") //pack utf-8 -> utf-16le
	{
		$value = mb_convert_encoding($value, $to, $from);
		return self::p_cuint(strlen($value)).$value;
	}
	
	//@throws eam_pack_exception(20101)
	public static function un_string($packed_data, &$offset, $from = "UTF-16LE", $to = "UTF-8") //unpack utf-16le -> utf-8
	{
		$length = self::un_cuint($packed_data, $offset);
		if (strlen($packed_data) < ($offset + $length))
			throw new eam_pack_exception(20101);
		
		$output = mb_convert_encoding(substr($packed_data, $offset, $length), $to, $from);
		$offset += $length;
		return $output;
	}
	
	public static function p_string_8($value)
	{
		return self::p_string($value, "UTF-8");
	}
	public static function un_string_8($packed_data, &$offset)
	{
		return self::un_string($packed_data, $offset, "UTF-8");
	}
	public static function p_string_16be($value)
	{
		return self::p_string($value, "UTF-16BE");
	}
	public static function un_string_16be($packed_data, &$offset)
	{
		return self::un_string($packed_data, $offset, "UTF16-BE");
	}
	
	//=== octet === ==========================================================================================================================================================
	public static function p_octet($value)
	{
		$value = pack("H*", $value);
		return self::p_cuint(strlen($value)).$value;
	}
	
	//@throws eam_pack_exception(20101)
	public static function un_octet($packed_data, &$offset)
	{
		$length = self::un_cuint($packed_data, $offset);
		if (strlen($packed_data) < ($offset + $length))
			throw new eam_pack_exception(20101);
		
		$output = unpack("H*", substr($packed_data, $offset, $length));
		$offset += $length;
		return $output[1];
	}
	
	//=== float === ==========================================================================================================================================================
	public static function p_float_rev($value)
	{
		return strrev(pack("f", $value));
	}
	
	//@throws eam_pack_exception(20101)
	public static function un_float_rev($packed_data, &$offset)
	{
		$output = @unpack("f", strrev(substr($packed_data, $offset, 4)));
		if ($output === false)
			throw new eam_pack_exception(20101);
		
		$offset += 4;
		return $output[1];
	}
	
	//=== structure === ==========================================================================================================================================================
	
	private static $structures = [
		'special_types' => [
			//'type_name' => ['pack_function_name', 'unpack_function_name'],
			'cuint' => ['p_cuint', 'un_cuint'],
			'string' => ['p_string', 'un_string'],
			'string8' => ['p_string_8', 'un_string_8'],
			'string16be' => ['p_string_16be', 'un_string_16be'],
			'octet' => ['p_octet', 'un_octet'],
			'float_rev' => ['p_float_rev', 'un_float_rev'],
		],
		'pw' => [
			//'struct_name' => "type[\[counter_type\]]=[size]=name[/type[\[counter_type\]]=[size]=name]",
			'RoleForbid' => "C==type/N==time/N==create_time/string==reason",
			'RoleInventory' =>  "N==id/N==pos/N==count/N==max_count/octet==data/N==proctype/N==expire_date/N==guid1/N==guid2/N==mask",
			'ShopItem' => "RoleInventory==item/N==price/N==reserved1/N==reserved2",
			'MailHeader' => "C==id/N==sender/C==sender_type/N==recv_time/string==title/N==send_time/C==attribute/string==sender_name",
			'playerlist' => "N==roleid",
			'RoleBase' => "C==bversion/N==roleid/string==rolename/N==race/N==cls/C==gender/octet==custom_data/octet==config_data/N==custom_stamp/C==status/N==delete_time/N==create_time/N==lastlogin_time/RoleForbid[]==forbid/octet==help_states/N==spouse/N==userid/octet==cross_data/C==reserved2/C==reserved3/C==reserved4",
			'RoleStatus' => "C==sversion/N==lvl/N==lvl2/N==exp/N==sp/N==pp/N==hp/N==mp/float_rev==posX/float_rev==posY/float_rev==posZ/N==worldtag/N==invader_state/N==invader_time/N==pariah_time/N==reputation/octet==custom_status/octet==filter_data/octet==charactermode/octet==inctancekeylist/N==dbltime_expire/N==dbltime_mode/N==dbltime_begin/N==dbltime_used/N==dbltime_max/N==time_used/octet==dbltime_data/n==store_size/octet==petcorral/octet==property/octet==var_data/octet==skills/octet==storehousepasswd/octet==waypointlist/octet==coolingtime/octet==npc_relation/octet==multi_exp_ctrl/octet==storage_task/octet==faction_contrib/octet==force_data/octet==online_award/octet==profit_time_data/octet==country_data/octet==king_data/octet==meridian_data/octet==extraprop/octet==title_data/octet==reincarnation_data/octet==realm_data/C==reserved4/C==reserved5",
			'RolePocket' => "N==capacity/N==timestamp/N==money/RoleInventory[]==items/N==reserved1/N==reserved2",
			'RoleEquipment' => "RoleInventory[]==items",
			'RoleStorehouse' => "N==capacity/N==money/RoleInventory[]==items/C==size1/C==size2/RoleInventory[]==dress/RoleInventory[]==material/C==size3/RoleInventory[]==generalcard/n==reserved",
			'RoleTask' => "octet==task_data/octet==task_complete/octet==task_finishtime/RoleInventory[]==items",
			'CrossInfoData' => "N==remote_roleid/N==data_timestamp/N==cross_timestamp/N==src_zoneid/N==reserved1/N==reserved2",
			'Member' => "N==roleid/C==role",
			'MemberInfo' => "N==roleid/C==level/C==occupation/C==role/n==loginday/C==online_status/string==rolename/string==nickname/N==contrib/C==delayexpel/N==expeltime",
			'FactionAlliance' => "N==factionid/N==end_time",
			'FactionHostile' => "N==factionid/N==end_time",
			'FactionRelationApply' => "N==type/N==factionid/N==end_time",
			'GMControlGame' => "N==gsid/N==retcode",
			'UserStorehouse' => "N==capacity/N==money/RoleInventory[]==items/N==reserved1/N==reserved2/N==reserved3/N==reserved4",
			'UserFaction' => "N==roleid/string==name/N==factionid/C==cls/C==role/octet==delayexpel/octet==extend/string==nickname",
			'RoleData' => "RoleBase==base/RoleStatus==status/RolePocket==pocket/RoleEquipment==equipment/RoleStorehouse==storehouse/RoleTask==task",
			'ShopDetail' => "N==roleid/N==shoptype/N==status/N==create_time/N==expire_time/N==money/RoleInventory[]==yinpiao/ShopItem[]==b_list/ShopItem[]==s_list/RoleInventory[]==storage/N==reserved1/N==reserved2/N==reserved3/N==reserved4",
			'PlayerInfo' => "N==userid/N==roleid/N==link_id/N==localsid/N==gs_id/C==status/string==rolename",
			'RoleIdName' => "N==roleid/string==rolename",
			'Mail' => "MailHeader==header/string==context/RoleInventory==attach_obj/N==attach_money",
			'PlayerConsumeInfo' => "N==roleid/N==level/N==login_ip/N==cash_add/N==mall_consumption/N==avg_online_time",
			'StockLog' => "N==tid/N==time/n==result/n==volume/N==cost",
			'Pair' => "N==key/N==value",
			'User' => "N==logicuid/H=4=rolelist/N==cash/N==money/N==cash_add/N==cash_buy/N==cash_sell/N==cash_used/N==add_serial/N==use_serial/StockLog[]==exg_log/octet==addiction/octet==cash_password/Pair[]==autolock/C==status/RoleForbid[]==forbid/octet==reference/octet==consume_reward/octet==taskcounter/octet==cash_sysauction/octet==login_record/octet==mall_consumption/n==reserved32",
			'RoleInfo' => "C==version/N==roleid/string==rolename/N==race/N==cls/C==gender/N==level/N==level2/float_rev==posx/float_rev==posy/float_rev==posz/N==worldtag/octet==custom_data/N==custom_stamp/octet==custom_status/octet==charactermode/RoleInventory[]==equipment/C==status/N==delete_time/N==create_time/N==lastlogin_time/RoleForbid[]==forbid/N==referrer_role/N==cash_add/CrossInfoData==cross_data/octet==reincarnation_data/octet==realm_data",
			'FactionInfo' => "N==fid/string==name/C==level/Member==master/Member[]==members/string==announce/octet==sysinfo",
			'FactionDetail' => 'N==fid/string==name/C==level/N==master/string==announce/octet==sysinfo/MemberInfo[]==members/N==last_op_time/FactionAlliance[]==alliance/FactionHostile[]==hostile/FactionRelationApply[]==apply',
			'TerritoryDetail' => "n==id/n==level/N==owner/N==occupy_time/N==challenger/N==deposit/N==cutoff_time/N==battle_time/N==bonus_time/N==color/N==status/N==timeout/N==maxbonus/N==challenge_time/octet==challenger_details/C==reserved1/C==reserved2/C==reserved3",
			'Message' => "C==channel/string==src_rolename/N==src_roleid/string==dst_rolename/N==dst_roleid/string==message",
			'SysLog' => "N==roleid/N==time/N==ip/n==source/N==money/RoleInventory[]==items/N==reserved1/N==reserved2/N==reserved3/N==reserved4",
			'RoleNameHistory' => "string==oldname/N==rename_time",
			'UniqueData' => "C==vtype/octet==value/N==version/n==reserved",
			'GroupInfo' => "C==group_id/string==name",
			'FriendInfo' => "N==roleid/C==cls/C==group_id/string==name",
			'FriendList' => "GroupInfo[]==groups/FriendInfo[]==friends",
			'FriendExtInfo' => "N==userid/N==roleid/N==level/N==lastlogin_time/N==update_time/N==reserved1/N==reserved2/N==reserved3",
			'SendAUMailRecord' => "N==roleid/N==sendmail_time",
			'FriendExtra' => "FriendExtInfo[]==friend_ext_info/SendAUMailRecord[]==send_au_mail_record/N==reserved1/N==reserved2/N==reserved3/N==reserved4/N==reserved5",
			'FactionRelation' => "N==fid/N==last_op_time/FactionAlliance[]==alliance/FactionHostile[]==hostile/FactionRelationApply[]==apply/N==reserved1/N==reserved2/N==reserved3/N==reserved4/N==reserved5",
			'FactionFortressInfo' => "N==level/N==exp/N==exp_today/N==exp_today_time/N==tech_point/octet==technology/octet==material/octet==building/octet==common_value/octet==actived_spawner/C==reserved11/n==reserved12/N==reserved2/N==reserved3",
			'ChallengerInfo' => "N==fid/N==time/N==deposit",
			'FactionFortressInfo2' => "N==health/N==offence_faction/N==offence_start_time/N==offence_end_time/ChallengerInfo[]==challenge_list/N==reserved1/N==reserved2/N==reserved3",
			'FactionFortressDetail' => "N==fid/FactionFortressInfo==info/FactionFortressInfo2==info2/N==reserved1/N==reserved2/N==reserved3/N==reserved4/N==reserved5",
			'AuctionItem' => "N==auctionid/N==bidprice/N==binprice/N==end_time/N==itemid/n==count/N==seller/N==bidder",
			'AuctionDetail' => "AuctionItem==info/n==category/N==baseprice/N==deposit/N==elapse_time/N==prolong/N==reserved1/N==reserved2/N==reserved3/RoleInventory==item",
			'StockOrder' => "N==tid/N==time/N==userid/N==price/N==volume/C==status",
			'PlayerProfileData' => "n==game_time_mask/n==game_interest_mask/n==personal_interest_mask/C==age/C==zodiac/n==match_option_mask",
			'WaitDel' => "N==init_time",			
		],
	];
	
	private static $pack_formats = [
		'allowed' => ['a', 'A', 'h', 'H', 'c', 'C', 's', 'S', 'n', 'v', 'i', 'I', 'l', 'L', 'N', 'V', 'q', 'Q', 'J', 'P', 'f', 'd', 'x', 'X', 'Z', '@'],
		'1byte' => ['c', 'C', 'x', 'X'],
		'2byte' => ['s', 'S', 'n', 'v'],
		'4byte' => ['l', 'L', 'N', 'V', 'f'],
		'8byte' => ['q', 'Q', 'J', 'P'],
		'repeat' => ['H', 'h'],
	];

	public static function p_struct($structure, $input)
	{
		$re = '';
		
		$structure = explode("/", $structure);
		foreach ($structure as $value)
		{
			$value = explode("=", $value);
			if (empty($value[0]) OR empty($value[2]))
				throw new eam_pack_exception(20103);

			$type = $value[0];
			
			$counter_start = strpos($type, '[');
			if ($counter_start !== false)
			{
				if ((strpos($type, ']') - $counter_start) !== 1)
					$array_counter = substr($type, $counter_start + 1, strpos($type, ']') - $counter_start - 1);
				else
					$array_counter = 'cuint';
				
				$type = substr($type, 0 , $counter_start);
			}
			else
				$array_counter = false;
			
			$name = $value[2];

			if (in_array($type, self::$pack_formats['allowed']))
			{
				//'H' => 'H*'
				if (in_array($type, self::$pack_formats['repeat']))
					$type .= '*';
				
				$re .= pack($type, $input[$name]);
			}
			elseif (isset(self::$structures['special_types'][$type]))
				$re .= self::{self::$structures['special_types'][$type][0]}($input[$name]);
				//$re .= $structures['special_types'][$type][0]($input[$name]);
			elseif (isset(self::$structures['pw'][$type]))
			{
				if ($array_counter !== false)
				{
					$re .= self::p_struct($array_counter."==counter", ['counter' => count($input[$name])]);
					//if (!PackStruct($array_counter.'==counter', ['counter' => count($input[$name])], $re))
					//	return false;
					
					foreach ($input[$name] as $item)
					{
						$re .= self::p_struct(self::$structures['pw'][$type], $item);
						//if (!PackStruct($structures['pw'][$type], $item, $re))
						//	return false;
					}
				}
				else
				{
					$re .= self::p_struct(self::$structures['pw'][$type], $input[$name]);
					//if (!PackStruct($structures['pw'][$type], $input[$name], $re))
					//	return false;
				}
			}
			else
				throw new eam_pack_exception(20103);
			
			//var_dump(bin2hex($re));
			//var_dump($type, $size, $name);
		}
		return $re;
	}
	
	//@throws eam_pack_exception()
	public static function un_struct($structure, $packed_data, &$offset = 0)
	{
		$re = [];
		
		//N==logicuid/H=4=rolelist
		$structure = explode("/", $structure);
		foreach ($structure as $value)
		{
			//H=4=rolelist
			$value = explode("=", $value);
			if (empty($value[0]) OR empty($value[2]))
				throw new eam_pack_exception(20102); //!isset($type) OR !isset($name)
			
			//var_dump($value);
			//var_dump(bin2hex(substr($packed_data, $offset)));
			
			$type = $value[0];
			
			$counter_start = strpos($type, '[');
			if ($counter_start !== false)
			{
				if ((strpos($type, ']') - $counter_start) !== 1) //[some_type]
					$array_counter = substr($type, $counter_start + 1, strpos($type, ']') - $counter_start - 1);
				else //[]
					$array_counter = 'cuint';
				
				$type = substr($type, 0 , $counter_start);
			}
			else
				$array_counter = false;
						
			$size = (empty($value[1])) ? false : $value[1];
			$name = $value[2];
			
			if (in_array($type, self::$pack_formats['allowed']))
			{
				//['a' (nul-padded string), 'A' (space-padded string), 'h', 'H', 'i' (signed int), 'I' (unsigned int), 'd' (double), 'Z' (nul-padded string), '@' (nul-fill to absolute position)]
				if (in_array($type, self::$pack_formats['1byte'])) //1 byte types
					$size = 1;
				elseif (in_array($type, self::$pack_formats['2byte'])) //2 byte types
					$size = 2;
				elseif (in_array($type, self::$pack_formats['4byte'])) //4 byte types
					$size = 4;
				elseif (in_array($type, self::$pack_formats['8byte'])) //8 byte types
					$size = 8;
				elseif ($size === false) //custom size + !isset($size)
					throw new eam_pack_exception(20102); //!isset($size)
				
				//'H' => 'H*'
				if (in_array($type, self::$pack_formats['repeat']))
					$type .= '*';

				$unpacked = @unpack($type, substr($packed_data, $offset, $size));
				if ($unpacked === false)
					throw new eam_pack_exception(20101);
				
				$re[$name] = $unpacked[1];
				//$re += unpack($type.$name, substr($packed_data, $offset, $size));
				$offset += $size;
			}
			elseif (isset(self::$structures['special_types'][$type]))
			{
				$re[$name] = self::{self::$structures['special_types'][$type][1]}($packed_data, $offset);
				//if (!$structures['special_types'][$type][1]($packed_data, $re[$name], $offset))
				//	return false;
			}
			elseif (isset(self::$structures['pw'][$type]))
			{
				if ($array_counter !== false)
				{
					$counter = self::un_struct($array_counter."==counter", $packed_data, $offset);
					//if (!UnpackStruct($array_counter."==counter", $packed_data, $maxi, $offset))
					//	return false;
					$re[$name] = [];
					for ($i = 0; $i < $counter['counter']; $i++)
					{
						$re[$name][$i] = self::un_struct(self::$structures['pw'][$type], $packed_data, $offset);
						//if (!UnpackStruct($structures['pw'][$type], $packed_data, $re[$name][$i], $offset))
						//	return false;
					}
				}
				else
				{
					$re[$name] = self::un_struct(self::$structures['pw'][$type], $packed_data, $offset);
					//if (!UnpackStruct($structures['pw'][$type], $packed_data, $re[$name], $offset))
					//	return false;
				}
			}
			else
				throw new eam_pack_exception(20102, null, ['type' => $type]); //unknown type
			
			//var_dump($re, $offset);
			//var_dump($type, $size, $name);
		}
		return $re;
	}

	//returns true / throws exceptions on bad response
	//@throws eam_socket_exception / eam_pack_exception() from unpack
	public static function PW_send($service, $opcode, $data, $passestablished, &$output = false, $new_recv_len = null)
	{
		//checking config vars
		if (!isset(self::$config['host']))
			throw new eam_packets_exception(20104, null, ['var' => 'host']);
		if (!isset(self::$config['port'][$service]))
			throw new eam_packets_exception(20104, null, ['var' => 'service-'.$service]);

		//creating and connecting socket
		$socket = @socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
		if ($socket === false)
			throw new eam_socket_exception(20105, null, self::get_socket_error());
		
		if (@socket_connect($socket, self::$config['host'], self::$config['port'][$service]) === false)
			throw new eam_socket_exception(20105, null, self::get_socket_error());

		socket_set_block($socket);
		
		if ($passestablished)
			socket_recv($socket, $tmp, 1024, 0); //???
		
		//sending
		$send_data = self::p_cuint($opcode).self::p_cuint(strlen($data)).$data;
		$send = socket_send($socket, $send_data, strlen($send_data), 0);
		if ($send !== strlen($send_data))
			throw new eam_socket_exception(20106, null, ['socket_send_output' => $send]);
		
		//[recieving]
		if ($output !== false)
		{
			$recv_len = (isset($new_recv_len) AND ($new_recv_len > 32)) ? $new_recv_len : 8192;
			
			$recv = socket_recv($socket, $output, $recv_len, 0);
			if ($recv === false)
				throw new eam_socket_exception(20105, null, self::get_socket_error());
			
			//checking response length			
			$offset = 0;
			$recv_opcode = self::un_cuint($output, $offset);
			$recv_len = self::un_cuint($output, $offset);
			
			if (($recv_len + $offset) > $recv)
			{
				$output = '';
				
				if (!isset($new_recv_len))
					//2nd try with new length
					return self::PW_send($service, $opcode, $data, $passestablished, $output, ($recv_len + $offset));
				else //if 2nd try failed (corrupted output)
					throw new eam_socket_exception(20107, null, ['pw_opcode' => $opcode, 'data' => bin2hex($data)]);
			}
		}
		
		//gg
		socket_set_nonblock($socket);
		socket_close($socket);

		return true;
	}
	
	private static function get_socket_error()
	{
		return [
			'socket_last_error' => socket_last_error(),
			'socket_strerror' => socket_strerror(socket_last_error())
		];
	}
}

/**
 * Perfect World socket conversation
 * 
 * @author Enellor
 */
class eam_pw_packets extends eam_module
{	
	/**
	 * @example $output = eam_pw_packets::get_role_data(1024);
	 * @param int $role_id
	 * @return array roledata: RoleData
	 * @throws eam_pw_packets_exception
	 */
	public static function get_role_data($role_id)
	{
		$query = eam_packets_lib::p_struct("N==q/N==roleid", ['q' => -1, 'roleid' => $role_id]);
		eam_packets_lib::PW_send("database", 8003, $query, false, $response);
		
		$offset = 0; //for final check
		$output = eam_packets_lib::un_struct("cuint==opcode/cuint==length/H=4=dbretcode/N==retcode/RoleData==role", $response, $offset);
		
		//checking unpack result
		if ($offset !== strlen($response))
			throw new eam_pw_packets_exception(20108, null, ['query' => bin2hex($query)]);
		
		//analyzing server response
		if ($output['retcode'] !== 0) //60 = wrong roleid?
			throw new eam_pw_packets_exception(20109, null, ['query' => bin2hex($query)]);		
		
		return $output;
	}
	
	/**
	 * disconnect role
	 * @example eam_pw_packets::disconnect_role(1024);
	 * @param int $role_id
	 * @param int $provider_link_id ?
	 * @param int $localsid ?
	 * @param int $gameid ?
	 */
	public static function disconnect_role($role_id, $provider_link_id = 1, $localsid = 1, $gameid = 1) //no_check
	{
		$query = eam_packets_lib::p_struct("N==roleid/N==provider_link_id/N==localsid/N==gameid", ['roleid' => $role_id, 'provider_link_id' => $provider_link_id, 'localsid' => $localsid, 'gameid' => $gameid]);
		eam_packets_lib::PW_send("provider", 106, $query, false);
	}
}