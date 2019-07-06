import "androguard"
import "cuckoo"


rule YaYaCharger: rule0 {
	meta:
		author = "YaYaGen -- Yet Another Yara Rule Generator (*) v0.4_winter17/18"
		date = "03 Jan 2018"
		url = "https://koodous.com/apks?search=efb1a6c795b81d31a15e1d49790d59ff3e474c430956340ae447364568033c03%20OR%2058eb6c368e129b17559bdeacb3aed4d9a5d3596f774cf5ed3fdcf51775232ba0%20OR%20761c805132d2080ce6d68d117bb25a297570dbf9a6cb510fcd68bf99de8e3a39"

	condition:
		androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED") and 
		androguard.filter("android.intent.action.ACTION_EXTERNAL_APPLICATIONS_AVAILABLE") and 
		androguard.filter("android.intent.action.BOOT_COMPLETED") and 
		androguard.filter("com.android.vending.INSTALL_REFERRER") and 

		androguard.permission("android.permission.ACCESS_NETWORK_STATE") and 
		androguard.permission("android.permission.CAMERA") and 
		androguard.permission("android.permission.INTERNET") and 
		androguard.permission("android.permission.READ_PHONE_STATE") and 
		androguard.permission("android.permission.READ_SMS") and 
		androguard.permission("android.permission.RECEIVE_BOOT_COMPLETED") and 
		androguard.permission("android.permission.SYSTEM_ALERT_WINDOW") and 
		androguard.permission("android.permission.WAKE_LOCK")
}