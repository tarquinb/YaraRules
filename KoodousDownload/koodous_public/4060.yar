import "androguard"
import "cuckoo"


rule YaYaSkyGo: rule0 {
	meta:
		author = "YaYaGen -- Yet Another Yara Rule Generator (*) v0.4_winter17/18"
		digest = "4bc62d21b53bd6f67c44f8a74295d8352b08deb0613c31404bffa9e97749a23f"
		date = "30 Jan 2018"

	condition:
		androguard.filter("android.intent.action.BOOT_COMPLETED") and 
		androguard.filter("com.google.android.c2dm.intent.RECEIVE") and 

		androguard.functionality.dynamic_broadcast.class(/Landroid\/support\/v4\/media\/TransportMediatorJellybeanMR2\;/) and 
		androguard.functionality.dynamic_broadcast.code(/invoke\-virtual\ v0\,\ v1\,\ Landroid\/content\/Context\;\-\>unregisterReceiver\(Landroid\/content\/BroadcastReceiver\;\)V/) and 
		androguard.functionality.dynamic_broadcast.code(/invoke\-virtual\ v0\,\ v1\,\ v2\,\ Landroid\/content\/Context\;\-\>registerReceiver\(Landroid\/content\/BroadcastReceiver\;\ Landroid\/content\/IntentFilter\;\)Landroid\/content\/Intent\;/) and 
		androguard.functionality.dynamic_broadcast.method(/windowAttached/) and 
		androguard.functionality.dynamic_broadcast.method(/windowDetached/) and 
		androguard.functionality.run_binary.code(/invoke\-static\ Ljava\/lang\/Runtime\;\-\>getRuntime\(\)Ljava\/lang\/Runtime\;/) and 
		androguard.functionality.socket.class(/Landroid\/support\/v4\/app\/NotificationManagerCompat\$SideChannelManager\;/) and 
		androguard.functionality.socket.code(/invoke\-interface\ v1\,\ v2\,\ Landroid\/support\/v4\/app\/NotificationManagerCompat\$Task\;\-\>send\(Landroid\/support\/v4\/app\/INotificationSideChannel\;\)V/) and 
		androguard.functionality.socket.method(/processListenerQueue/) and 

		androguard.permission("android.permission.ACCESS_NETWORK_STATE") and 
		androguard.permission("android.permission.ACCESS_WIFI_STATE") and 
		androguard.permission("android.permission.INTERNET") and 
		androguard.permission("android.permission.READ_PHONE_STATE") and 
		androguard.permission("android.permission.READ_SMS") and 
		androguard.permission("android.permission.RECEIVE_BOOT_COMPLETED") and 
		androguard.permission("android.permission.WAKE_LOCK") and 
		androguard.permission("android.permission.WRITE_EXTERNAL_STORAGE") and 
		androguard.permission("com.google.android.c2dm.permission.RECEIVE")
}