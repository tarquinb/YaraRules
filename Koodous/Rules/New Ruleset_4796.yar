import "androguard"
import "cuckoo"


rule YaYa: rule1 {
	meta:
		author = "YaYaGen -- Yet Another Yara Rule Generator (*) v0.5_summer18"
		date = "09 Aug 2018"
		url = "https://koodous.com/apks?search=tag:sms-fraud"

	condition:
		androguard.filter("android.net.conn.CONNECTIVITY_CHANGE") and 

		androguard.functionality.crypto.method(/a/) and 
		androguard.functionality.imei.code(/invoke\-virtual\ v0\,\ Landroid\/telephony\/TelephonyManager\;\-\>getDeviceId\(\)Ljava\/lang\/String\;/) and 
		androguard.functionality.imsi.code(/invoke\-virtual\ v0\,\ Landroid\/telephony\/TelephonyManager\;\-\>getSubscriberId\(\)Ljava\/lang\/String\;/) and 
		androguard.functionality.run_binary.code(/invoke\-static\ Ljava\/lang\/Runtime\;\-\>getRuntime\(\)Ljava\/lang\/Runtime\;/) and 

		androguard.permission("android.permission.ACCESS_COARSE_LOCATION") and 
		androguard.permission("android.permission.ACCESS_FINE_LOCATION") and 
		androguard.permission("android.permission.ACCESS_NETWORK_STATE") and 
		androguard.permission("android.permission.ACCESS_WIFI_STATE") and 
		androguard.permission("android.permission.CHANGE_NETWORK_STATE") and 
		androguard.permission("android.permission.CHANGE_WIFI_STATE") and 
		androguard.permission("android.permission.DISABLE_KEYGUARD") and 
		androguard.permission("android.permission.GET_TASKS") and 
		androguard.permission("android.permission.INTERNET") and 
		androguard.permission("android.permission.MOUNT_UNMOUNT_FILESYSTEMS") and 
		androguard.permission("android.permission.READ_EXTERNAL_STORAGE") and 
		androguard.permission("android.permission.READ_PHONE_STATE") and 
		androguard.permission("android.permission.READ_SMS") and 
		androguard.permission("android.permission.RECEIVE_SMS") and 
		androguard.permission("android.permission.SEND_SMS") and 
		androguard.permission("android.permission.VIBRATE") and 
		androguard.permission("android.permission.WAKE_LOCK") and 
		androguard.permission("android.permission.WRITE_EXTERNAL_STORAGE") and 
		androguard.permission("android.permission.WRITE_SETTINGS") and 
		androguard.permission("android.permission.WRITE_SMS")
}