import "androguard"
import "file"
import "droidbox"


rule koodous : official
{
	meta:
		description = "This rule detects the SmsZombie application"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:

	condition:
		androguard.package_name("com.xqxmn18.pic ") and
		androguard.app_name("小清新美女动态壁纸 ") and
		androguard.activity(/com.xqxmn18.pic.jifenActivity/i) and
		androguard.service(/com.xqxmn18.pic.BXWallActivity/)and 
		androguard.filter("android.intent.action.MAIN")and
		androguard.certificate.sha1("5B8F3D7427B334BC30B58BAA841DF3C87BBE5DC2") and
		androguard.functionality.run_binary.code(/invoke-static Ljava\/lang\/Runtime;->getRuntime()Ljava\/lang\/Runtime;/)and
		androguard.functionality.dynamic_broadcast_receiver.code(/invoke-virtual v6, v7, v1, Lcom\/xqxmn18\/pic\/BXWallActivity;->registerReceiver(Landroid\/content\/BroadcastReceiver; Landroid\/content\/IntentFilter;)Landroid\/content\/Intent;/)and
		androguard.functionality.dynamic_broadcast_receiver.code(/invoke-virtual v12, v7, v2, Lcom\/xqxmn18\/pic\/jifenActivity;->registerReceiver(Landroid\/content\/BroadcastReceiver; Landroid\/content\/IntentFilter;)Landroid\/content\/Intent;/)and
		androguard.functionality.dynamic_broadcast_receiver.code(/invoke-virtual v12, v7, v1, Lcom\/xqxmn18\/pic\/jifenActivity;->registerReceiver(Landroid\/content\/BroadcastReceiver; Landroid\/content\/IntentFilter;)Landroid\/content\/Intent;/)and
		droidbox.dexcalls.Process_Name("com.xqxmn18.pic")and
		droidbox.read_file.name("/data/app/com.xqxmn18.pic-1.apk") or 
		droidbox.read.data(/504b0506000000001500150095050000534a19000000504b01020a000a0000000000cf100441e977877b7ea000007ea000000e00040000000000000000000000000000006173736574732f6133332e6a7067feca0000504b01021400140008000800c1130441ab8e8caec5000000840100001300000000000000000000000000aea000007265732f6c61796f75742f6d61696e2e786d6c504b01021400140008000800c11304416f489416690200002c0700001400000000000000000000000000b4a100007265732f6c61796f75742f6d61696e312e786d6c504b01021400140008000800c11304412d822fe5fd0200009008000013000000000000000000000000005fa40000416e64726f69644d616e69666573742e786d6c504b01020a000a0000000000c2130441a5b9ba042c0b00002c0b00000e000000000000000000000000009da700007265736f75726365732e61727363504b01020a000a0000000000c4a5024139cb669b96fe010096fe01001600000000000000000000000000f5b200007265732f6472617761626c652d76312f61312e6a7067504b01020a000a0000000000cea50241cd9c81055f6108005f6108001600000000000000000000000000bfb102007265732f6472617761626c652d76312f61322e6a7067504b01020a000a0000000000d2a50241c792e45ccbf80000cbf80000160000000000/)
	
		
}