import "androguard"
import "file"
import "droidbox"

rule SmsZombie
{
	meta:
		description = "This rule detects the SmsZombie application"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
	

	condition:
		androguard.package_name("com.gmdcd.pic") and
		androguard.app_name("国模大尺度动态壁纸") and
		androguard.activity(/com.gmdcd.pic.jifenActivity /i) and
		androguard.certificate.sha1("5B8F3D7427B334BC30B58BAA841DF3C87BBE5DC2") and
		androguard.filter("android.intent.action.MAIN")and
		androguard.services("com.gmdcd.pic.BXWallActivity")and
		androguard.functionality.run_binary.code(/invoke-static Ljava\/lang\/Runtime;->getRuntime()Ljava\/lang\/Runtime;/)and
		androguard.functionality.dynamic_broadcast_receiver.code(/invoke-virtual v6, v7, v1, Lcom\/gmdcd\/pic\/BXWallActivity;->registerReceiver(Landroid\/content\/BroadcastReceiver; Landroid\/content\/IntentFilter;)Landroid\/content\/Intent;/)and
		androguard.functionality.dynamic_broadcast_receiver.code(/invoke-virtual v12, v7, v2, Lcom\/gmdcd\/pic\/jifenActivity;->registerReceiver(Landroid\/content\/BroadcastReceiver; Landroid\/content\/IntentFilter;)Landroid\/content\/Intent;/)and
		androguard.functionality.dynamic_broadcast_receiver.code(/invoke-virtual v12, v7, v1, Lcom\/gmdcd\/pic\/jifenActivity;->registerReceiver(Landroid\/content\/BroadcastReceiver; Landroid\/content\/IntentFilter;)Landroid\/content\/Intent;/)and
		droidbox.Dexcalls("com.gmdcd.pic ")and
		droidbox.read.filename("/data/app/com.gmdcd.pic-1.apk ") or
	
		droidbox.read.data(/504b050600000000130013000d050000710509000000504b01020a000a0000000000cf100441e977877b7ea000007ea000000e00040000000000000000000000000000006173736574732f6133332e6a7067feca0000504b01021400140008000800f51004412e6cd2f9c5000000840100001300000000000000000000000000aea000007265732f6c61796f75742f6d61696e2e786d6c504b01021400140008000800f5100441ef63e22b6a0200002c0700001400000000000000000000000000b4a100007265732f6c61796f75742f6d61696e312e786d6c504b01021400140008000800f5100441efceb072fa0200008c080000130000000000000000000000000060a40000416e64726f69644d616e69666573742e786d6c504b01020a000a0000000000f610044168cec4845c0a00005c0a00000e000000000000000000000000009ba700007265736f75726365732e61727363504b01020a000a00000000001ba60241ab01c23ca7880000a7880000160000000000000000000000000023b200007265732f6472617761626c652d76312f61312e6a7067504b01020a000a000000000017a60241fb3d0aca9f6800009f6800001600000000000000000000000000fe3a01007265732f6472617761626c652d76312f61322e6a7067504b01020a000a000000000011a60241093cbfc47959010079590100160000000000/i)
		
}