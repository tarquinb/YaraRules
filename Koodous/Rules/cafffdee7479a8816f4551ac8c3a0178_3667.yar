import "androguard"
import "file"
import "droidbox"



rule koodous : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$a = {63 6F 6D 24 6B 6F 6F 64 6F 75 73 24 61 6E 64 72 6F 69 64}

	condition:
		androguard.package_name("com.lzll.pic ") and
		androguard.app_name("泷泽萝拉动态壁纸 ") and
		androguard.activity(/com.lzll.pic.jifenActivity /i) and
		androguard.certificate.sha1("5B8F3D7427B334BC30B58BAA841DF3C87BBE5DC2") and
		androguard.service(/com.lzll.pic.BXWallActivity/)and 
		androguard.filter("android.intent.action.MAIN")and
		androguard.functionality.run_binary.code(/invoke-static Ljava\/lang\/Runtime;->getRuntime()Ljava\/lang\/Runtime;/)and
		androguard.functionality.dynamic_broadcast_receiver.code(/invoke-virtual v6, v7, v1, Lcom\/xqxmn18\/pic\/BXWallActivity;->registerReceiver(Landroid\/content\/BroadcastReceiver; Landroid\/content\/IntentFilter;)Landroid\/content\/Intent;/)and
		androguard.functionality.dynamic_broadcast_receiver.code(/invoke-virtual v12, v7, v2, Lcom\/lzll\/pic\/jifenActivity;->registerReceiver(Landroid\/content\/BroadcastReceiver; Landroid\/content\/IntentFilter;)Landroid\/content\/Intent;/)and
		androguard.functionality.dynamic_broadcast_receiver.code(/invoke-virtual v12, v7, v1, Lcom\/lzll\/pic\/jifenActivity;->registerReceiver(Landroid\/content\/BroadcastReceiver; Landroid\/content\/IntentFilter;)Landroid\/content\/Intent;/)and
		droidbox.dexcalls.Process_Name("com.lzll.pic")and
		droidbox.read_file.name("/data/app/com.lzll.pic-1.apk") or 
		droidbox.read.data(/504b050600000000170017001e060000c2890c000000504b01020a000a00000000009452ff40a6fb606db39f0000b39f00000e00040000000000000000000000000000006173736574732f6133332e6a7067feca0000504b01021400140008000800ef53ff40b176157dc5000000840100001300000000000000000000000000e39f00007265732f6c61796f75742f6d61696e2e786d6c504b01021400140008000800ef53ff40f42a4e5a6a0200002c0700001400000000000000000000000000e9a000007265732f6c61796f75742f6d61696e312e786d6c504b01021400140008000800ef53ff4054010fe6fa0200008c080000130000000000000000000000000095a30000416e64726f69644d616e69666573742e786d6c504b01020a000a0000000000ad53ff40a5a97bc0fc0b0000fc0b00000e00000000000000000000000000d0a600007265736f75726365732e61727363504b01020a000a00000000008751ff40f93c9fa55aa000005aa000001600000000000000000000000000f8b200007265732f6472617761626c652d76312f61312e6a7067504b01020a000a00000000009d51ff4061d55b69e6920000e69200001600000000000000000000000000865301007265732f6472617761626c652d76312f61322e6a7067504b01020a000a0000000000a251ff40d414d01a3b1001003b100100160000000000/)
	
		
}