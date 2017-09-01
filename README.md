# eam_pw_packets

* add more structures here: **pw_packets.php -> class eam_packets_lib -> var $structures['pw']**
* add more packets here: **pw_packets.php -> class eam_pw_packets**


## Example:
$RoleData = eam_pw_packets::get_role_data(1024);

$RoleData dump:

```
index.php:20:
array (size=5)
  'opcode' => int 8003
  'length' => int 6864
  'dbretcode' => string '7fffffff' (length=8)
  'retcode' => int 0
  'role' => 
    array (size=6)
      'base' => 
        array (size=21)
          'bversion' => int 1
          'roleid' => int 1024
          'rolename' => string 'dawdqewq' (length=8)
          'race' => int 5
          'cls' => int 7
          'gender' => int 1
          'custom_data' => string '01700010667580001700170032788b0005007e80ab8080717b6c71709c868e89807380746d868080808069014b01320209008b7c777480697e8b7c777480697e0700600173728480808073728480808001001000839279a30f00808c5b0056005e007a677d800e0067677e7e1600808c1701a701000000000000b201b4010000fffffffff2ebeeff909090ff94aae3ffb7e9e7ff987a4effffffffff0000000000000000ffffffff787b757a7a760000' (length=352)
          'config_data' => string '03000000780193606360e0668000262005c220c008a1186a81344cac10c86681f2f9a1f2ac48f22021a07160f57c200e1070402886e540fa3f0100553a4a8d86c068080cd11000e57f50d901c220360880ca0f109b198a416c50b9815e1cf000c5863a180e7e68f8f08b89e1e157560f602402eb06463080460cac2e00c51d83c32317b07083b58b21831183f110883c58bd46c8a9bdd381fe2302c0d23ab2b9c86c58265007069c32c43c487842482320c5c2c8f80f189aa09a76800123d8e54c08f743631e48815301285b8324e15c100b998b260be222f4823c07560e66d8b138b118b19802491077608082230343833d13d88d60b7029d01723203a300955d2502f7202c59e1a601079a5299' (length=540)
          'custom_stamp' => int 0
          'status' => int 1
          'delete_time' => int 0
          'create_time' => int 1461428071
          'lastlogin_time' => int 1463930541
          'forbid' => 
            array (size=4)
              0 => 
                array (size=4)
                  'type' => int 101
                  'time' => int 1
                  'create_time' => int 1463269054
                  'reason' => string '1' (length=1)
              1 => 
                array (size=4)
                  'type' => int 100
                  'time' => int 1
                  'create_time' => int 1463269076
                  'reason' => string 'res' (length=3)
              2 => 
                array (size=4)
                  'type' => int 103
                  'time' => int 120
                  'create_time' => int 1463268528
                  'reason' => string '23' (length=2)
              3 => 
                array (size=4)
                  'type' => int 102
                  'time' => int 120
                  'create_time' => int 1463268368
                  'reason' => string '2' (length=1)
          'help_states' => string '01001e009d93a793a893a993aa93ab93bb93c593f303f483fd8307841184db87e5872584ef872f84f987c38b03880d8817882188ab8f2b88b58f35883f8893937f80' (length=132)
          'spouse' => int 0
          'userid' => int 1024
          'cross_data' => string '' (length=0)
          'reserved2' => int 0
          'reserved3' => int 0
          'reserved4' => int 0
      'status' => 
        array (size=51)
          'sversion' => int 1
          'lvl' => int 100
          'lvl2' => int 0
          'exp' => int 101000
          'sp' => int 22825
          'pp' => int 471
          'hp' => int 70
          'mp' => int 252
          'posX' => float 1845.1319580078
          'posY' => float 222.19876098633
          'posZ' => float 1338.6096191406
          'worldtag' => int 1
          'invader_state' => int 0
          'invader_time' => int 0
          'pariah_time' => int 0
          'reputation' => int 619
          'custom_status' => string '' (length=0)
          'filter_data' => string '00000000' (length=8)
          'charactermode' => string '0100000001000000' (length=16)
          'inctancekeylist' => string '000000002600000069000000689f1b576a000000689f1b576b000000689f1b576c000000689f1b576d000000689f1b576e000000689f1b576f000000689f1b5772000000689f1b5773000000689f1b5774000000689f1b5775000000689f1b577b000000689f1b577c000000689f1b577d000000689f1b577e000000689f1b577f000000689f1b5780000000689f1b5781000000689f1b57e6000000689f1b57e7000000689f1b57e8000000689f1b57e9000000689f1b57ea000000689f1b57eb000000689f1b5783000000689f1b5787000000689f1b578a000000689f1b578b000000689f1b578d000000689f1b5790000000689f1b5791000000689f1b5792000000689f1b5794000000689f1b5795000000689f1b57a2000000689f1b57a6000000689f1b57a7000000689f1b5793000000689f1b57000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006900000000040000679f1b576a00000000040000679f1b576b00000000040000679f1b576c00000000040000679f1b576d00000000040000679f1b576e00000000040000679f1b576f00000000040000679f1b577200000000040000679f1b577300000000040000679f1b577400000000040000679f1b577500000000040000679f1b577b00000000040000679f1b577c00000000040000679f1b577d00000000040000679f1b577e00000000040000679f1b577f00000000040000679f1b578000000000040000679f1b578100000000040000679f1b578300000000040000679f1b578700000000040000679f1b578a00000000040000679f1b578b00000000040000679f1b578d00000000040000679f1b579000000000040000679f1b579100000000040000679f1b579200000000040000679f1b579300000000040000679f1b579400000000040000679f1b579500000000040000679f1b57a200000000040000679f1b57a600000000040000679f1b57a700000000040000679f1b57e600000000040000679f1b57e700000000040000679f1b57e800000000040000679f1b57e900000000040000679f1b57ea00000000040000679f1b57eb00000000040000679f1b57' (length=2144)
          'dbltime_expire' => int 0
          'dbltime_mode' => int 0
          'dbltime_begin' => int 1463954400
          'dbltime_used' => int 0
          'dbltime_max' => int 21600
          'time_used' => int 1705801
          'dbltime_data' => string '0100000000000000ac2d4257' (length=24)
          'store_size' => int 31616
          'petcorral' => string '00000004030000000080c000000000030000008b000000692300000000000071230000000000000000803f010000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000180c0000000000100000000000000692300000000000071230000000000000000803f010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000280c0000000000200000057000000b14a000000000000b24a0000000000000000803f01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' (length=1198)
          'property' => string '0700000012000000090000000a00000046000000fc0000000100000004000000000000409a999940000040400000a04000000000010000000100000010000000000020400000000000000000000000000000000000000000000000000000000000000000000000000000000001000000010000000000000000000000000000000000000000000000010000000000000000000000' (length=296)
          'var_data' => string '070000000000000000000000000000000100000000000000000000001000000000000000ffffffffaa0b0000020000000008000086000000842df0a6a47e3608' (length=128)
          'skills' => string '030000007100000000000000010000007d0000000000000001000000a70000000000000001000000' (length=80)
          'storehousepasswd' => string '' (length=0)
          'waypointlist' => string '5114' (length=4)
          'coolingtime' => string 'ffffffff00000000' (length=16)
          'npc_relation' => string '0001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' (length=1048)
          'multi_exp_ctrl' => string '000000000000000000000000000000006f9645570000000000eb4457' (length=56)
          'storage_task' => string '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' (length=1728)
          'faction_contrib' => string '000000000000000000000000' (length=24)
          'force_data' => string '0000000000000000000000000000000000' (length=34)
          'online_award' => string '0100000090694557c0a8000000000000' (length=32)
          'profit_time_data' => string 'c0a80000d0c04457' (length=16)
          'country_data' => string '' (length=0)
          'king_data' => string '' (length=0)
          'meridian_data' => string '0000000000000000000000000000000500000064000042320000000900000000000000000000000000000000000000000000000000000000' (length=112)
          'extraprop' => string '03000000011457307edd0002000000000000000000000000000000000003040000000a000000053c50b548570000000006000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' (length=200)
          'title_data' => string '150501000000150500000000' (length=24)
          'reincarnation_data' => string '000000000000000000000000000000000000' (length=36)
          'realm_data' => string '00000000000000000000000000000000' (length=32)
          'reserved4' => int 0
          'reserved5' => int 0
      'pocket' => 
        array (size=6)
          'capacity' => int 128
          'timestamp' => int 3459
          'money' => int 80102432
          'items' => 
            array (size=21)
              0 => 
                array (size=10)
                  'id' => int 15061
                  'pos' => int 0
                  'count' => int 1
                  'max_count' => int 100
                  'data' => string 'af230000' (length=8)
                  'proctype' => int 131080
                  'expire_date' => int 0
                  'guid1' => int 0
                  'guid2' => int 0
                  'mask' => int 0
              1 => 
                array (size=10)
                  'id' => int 41057
                  'pos' => int 1
                  'count' => int 3
                  'max_count' => int 9999
                  'data' => string '7f770000' (length=8)
                  'proctype' => int 16403
                  'expire_date' => int 0
                  'guid1' => int 0
                  'guid2' => int 0
                  'mask' => int 0
                  
              ... => []
              
              20 => 
                array (size=10)
                  'id' => int 2096
                  'pos' => int 120
                  'count' => int 1
                  'max_count' => int 1
                  'data' => string '0100000000000000020000000000000003000000' (length=40)
                  'proctype' => int 19
                  'expire_date' => int 0
                  'guid1' => int 0
                  'guid2' => int 0
                  'mask' => int 4096
          'reserved1' => int 0
          'reserved2' => int 0
      'equipment' => 
        array (size=1)
          'items' => 
            array (size=2)
              0 => 
                array (size=10)
                  'id' => int 2251
                  'pos' => int 0
                  'count' => int 1
                  'max_count' => int 1
                  'data' => string '0100ff02050000000000030062050000780500002c00030000000000240100000000000000000000030000000300000005000000060000001000000000004040000000000000000000000000' (length=152)
                  'proctype' => int 0
                  'expire_date' => int 0
                  'guid1' => int 0
                  'guid2' => int 0
                  'mask' => int 1
              1 => 
                array (size=10)
                  'id' => int 23754
                  'pos' => int 23
                  'count' => int 1
                  'max_count' => int 1
                  'data' => string '000000000100000000000000000000000100000000000000000000000000204e0000000000000000000001000000f6030100' (length=100)
                  'proctype' => int 23
                  'expire_date' => int 0
                  'guid1' => int 1463579224
                  'guid2' => int 16783024
                  'mask' => int 8388608
      'storehouse' => 
        array (size=10)
          'capacity' => int 16
          'money' => int 0
          'items' => 
            array (size=0)
              empty
          'size1' => int 0
          'size2' => int 0
          'dress' => 
            array (size=0)
              empty
          'material' => 
            array (size=0)
              empty
          'size3' => int 120
          'generalcard' => 
            array (size=0)
              empty
          'reserved' => int 0
      'task' => 
        array (size=4)
          'task_data' => string '161601000b0001008976ffffff01022a071a000000e4a10e0c000000000000000000000000000000f07700ffffff0225071a00000074c30e0c000000000000000000000000000000e44cffffffff022a071a000000acb0520e0000000000000000000000000000009478ffffff0402c9041a000000bccff00b000000000000000000000000000000967803ffffff02c4041a000000e4eef00b0000000000000000000000000000002e61ffffff0602c9041a0000003c2a2e0d000000000000000000000000000000306105ffffff02c3041a00000084442e0d0000000000000000000000000000003a19ffffff0802c9041a0000000c1190100000000000000000000000000000001b1b07ffffff02c3041a0000001c3a90100000000000000000000000000000007419ffffff0a02c9041a0000008c498b10000000000000000000000000000000151b09ffffff02bc041a000000cc648b10000000000000000000000000000000c36effffff0c02c9041a0000005c78780c000000000000000000000000000000ce6e0bffffff02b4041a0000007c9d780c0000000000000000000000000000002f6fffffff0e02c9041a000000bcd8710c000000000000000000000000000000386f0dffffff02ad041a0000005cf4710c000000000000000000000000000000fa6affffff1002c9041a0000008c15ad0c000000000000000000000000000000fc6a0fffffff02ad041a0000004c2fad0c000000000000000000000000000000b004ffffff1202c8041a0000001c46ba110000000000000000000000000000003b0711ffffff02ac041a0000006460ba11000000000000000000000000000000020dffffff14025b24090000001c1848110000000000000000000000000000000d1b13ffffff025b2409000000343648110000000000000000000000000000007e77ffffffff02d622090000009cf9ff0b000000000000000000000000000000' (length=1424)
          'task_complete' => string '0e0001005f040000ff0c0000000d0000010d00003c1900003d1900003e190000e6490000925000006473000051770000667700006a7800007e790000' (length=120)
          'task_finishtime' => string '01007e7747723c57' (length=16)
          'items' => 
            array (size=0)
              empty
```
