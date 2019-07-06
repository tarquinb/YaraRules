import "androguard"
import "cuckoo"


rule YaYaRuleEXOBOTDropped: rule0 {
	meta:
		author = "YaYaGen -- Yet Another Yara Rule Generator (*) v0.4_winter17/18"
		date = "19 Jan 2018"
		description = "Dropped apps: https://clientsidedetection.com/exobot_android_malware_spreading_via_google_play_store.html"

	condition:
		androguard.filter("android.provider.Telephony.SMS_RECEIVED") and 

		androguard.functionality.crypto.code(/invoke\-virtual\ v0\,\ Ljava\/security\/MessageDigest\;\-\>digest\(\)\[B/) and 
		androguard.functionality.crypto.code(/invoke\-virtual\ v6\,\ Ljava\/security\/MessageDigest\;\-\>digest\(\)\[B/) and 
		androguard.functionality.crypto.method(/a/) and 
		androguard.functionality.crypto.method(/b/) and 
		androguard.functionality.dynamic_broadcast.method(/onBind/) and 
		androguard.functionality.imei.class(/Landroid\/support\/v7\/a\/j\;/) and 
		androguard.functionality.imei.code(/invoke\-virtual\ v0\,\ Landroid\/telephony\/TelephonyManager\;\-\>getDeviceId\(\)Ljava\/lang\/String\;/) and 
		androguard.functionality.imei.code(/invoke\-virtual\ v10\,\ Landroid\/view\/KeyEvent\;\-\>getDeviceId\(\)I/) and 
		androguard.functionality.imei.method(/a/) and 
		androguard.functionality.imei.method(/b/) and

		androguard.permission("android.permission.ACCESS_FINE_LOCATION") and 
		androguard.permission("android.permission.ACCESS_NETWORK_STATE") and 
		androguard.permission("android.permission.ACCESS_WIFI_STATE") and 
		androguard.permission("android.permission.READ_CONTACTS")
}