import "androguard"


 rule YaYaSyringe {
	meta:
		author = "YaYaGen -- Yet Another Yara Rule Generator (!) v0.3_summer17"
		date = "13 Jul 2017"
		original = "1154:Syringe"

	condition:
		androguard.filter("android.intent.action.BATTERYCHECK") and 
		androguard.filter("android.intent.action.MAIN") and 
		androguard.filter("android.intent.action.MEDIA_MOUNTED") and 
		androguard.filter("android.intent.action.PACKAGE_ADDED") and 
		androguard.filter("android.intent.action.PACKAGE_FIRST_LAUNCH") and 
		androguard.filter("android.intent.action.USER_PRESENT") and 
		androguard.filter("android.intent.action.core") and 
		androguard.filter("android.intent.action.download") and 
		androguard.filter("android.net.conn.CONNECTIVITY_CHANGE") and 

		androguard.functionality.crypto.code(/invoke\-virtual\ v1\,\ Ljava\/security\/MessageDigest\;\-\>digest\(\)\[B/) and 
		androguard.functionality.crypto.method(/a/) and 
		androguard.functionality.socket.code(/invoke\-virtual\ v0\,\ Ljava\/net\/URL\;\-\>openConnection\(\)Ljava\/net\/URLConnection\;/) and 
		androguard.functionality.socket.code(/invoke\-virtual\ v4\,\ Ljava\/net\/URL\;\-\>openConnection\(\)Ljava\/net\/URLConnection\;/) and 

		androguard.number_of_services == 3 and 

		androguard.permission("android.permission.ACCESS_NETWORK_STATE") and 
		androguard.permission("android.permission.ACCESS_WIFI_STATE") and 
		androguard.permission("android.permission.GET_TASKS") and 
		androguard.permission("android.permission.INTERNET") and 
		androguard.permission("android.permission.READ_PHONE_STATE") and 
		androguard.permission("android.permission.SYSTEM_ALERT_WINDOW") and 
		androguard.permission("android.permission.WAKE_LOCK") and 
		androguard.permission("android.permission.WRITE_EXTERNAL_STORAGE") and 
		androguard.permission("com.android.launcher.permission.INSTALL_SHORTCUT") and 
		androguard.permission("com.android.launcher.permission.UNINSTALL_SHORTCUT") and 

		androguard.url("http://s.adslinkup.com/v2/ads/update/")
}