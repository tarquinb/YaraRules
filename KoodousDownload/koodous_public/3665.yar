import "androguard"
import "file"
import "droidbox"



rule koodous : official
{
	meta:
		description = "This rule detects the SmsZombie application "
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
	

	condition:
		androguard.package_name("com.hxmv696.pic") and
		androguard.app_name("寄国混血美女动态壁纸") and
		androguard.activity(/com.hxmv696.pic.jifenActivity /i) and
		androguard.services(/com.hxmv696.pic.BXWallActivity/)and
		androguard.filters(/android.intent.action.MAIN/)and
		androguard.certificate.sha1("5B8F3D7427B334BC30B58BAA841DF3C87BBE5DC2") and
		androguard.functionality.run_binary.code(/invoke-static Ljava\/lang\/Runtime;->getRuntime()Ljava\/lang\/Runtime;/)and
		androguard.functionality.dynamic_broadcast_receiver.code(/invoke-virtual v6, v7, v1, Lcom\/hxmv696\/pic\/BXWallActivity;->registerReceiver(Landroid\/content\/BroadcastReceiver; Landroid\/content\/IntentFilter;)Landroid\/content\/Intent;/)and
		androguard.functionality.dynamic_broadcast_receiver.code(/invoke-virtual v12, v7, v2, Lcom\/hxmv696\/pic\/jifenActivity;->registerReceiver(Landroid\/content\/BroadcastReceiver; Landroid\/content\/IntentFilter;)Landroid\/content\/Intent;/)and
		androguard.functionality.dynamic_broadcast_receiver.code(/invoke-virtual v12, v7, v1, Lcom\/hxmv696\/pic\/jifenActivity;->registerReceiver(Landroid\/content\/BroadcastReceiver; Landroid\/content\/IntentFilter;)Landroid\/content\/Intent;/)and
		droidbox.dexcalls.Process_Name("com.hxmv696.pic")and
		droidbox.read_file.name("/data/app/com.hxmv696.pic-1.apk ") or 
		droidbox.read.data(/504b05060000000012001200c90400006e7808000000504b01020a000a0000000000cf100441e977877b7ea000007ea000000e00040000000000000000000000000000006173736574732f6133332e6a7067feca0000504b01021400140008000800007b054139688743c4000000840100001300000000000000000000000000aea000007265732f6c61796f75742f6d61696e2e786d6c504b01021400140008000800007b054119b3edac6a0200002c0700001400000000000000000000000000b3a100007265732f6c61796f75742f6d61696e312e786d6c504b01021400140008000800007b0541369ffc7cfe0200009008000013000000000000000000000000005fa40000416e64726f69644d616e69666573742e786d6c504b01020a000a0000000000017b05416839bb9bf4090000f40900000e000000000000000000000000009ea700007265736f75726365732e61727363504b01020a000a0000000000c88c0441dd0885c9ea020200ea0202001600000000000000000000000000beb100007265732f6472617761626c652d76312f61312e6a7067504b01020a000a0000000000c78c04413115abefc0070100c00701001600000000000000000000000000dcb402007265732f6472617761626c652d76312f61322e6a7067504b01020a000a0000000000c58c04415a8ee50b3a0001003a000100160000000000/)
		
	
}