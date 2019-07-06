import "androguard"
import "cuckoo"


rule YaYaSexDrugVokrug: rule0 {
	meta:
		author = "YaYaGen -- Yet Another Yara Rule Generator (*) v0.4_winter17/18"
		date = "03 Jan 2018"
		url = "https://koodous.com/apks?search=f879be33af6de2529a0eda45d9d8130ce3eb7619ab3f2bade3ce5d09cbf4b4e5%20OR%203281da03967737a42c10d41f65bf39b47c229c11212b77d4920d6664722f4c53%20OR%207ec5240358586a00f3cc45144737439792994e35718bf8c109e8488da345953c"

	condition:

		androguard.filter("android.intent.action.QUICKBOOT_POWERON") and 

		androguard.functionality.imei.code(/invoke\-virtual\ v0\,\ Landroid\/telephony\/TelephonyManager\;\-\>getDeviceId\(\)Ljava\/lang\/String\;/) and 
		androguard.functionality.installed_app.code(/invoke\-virtual\ v0\,\ v1\,\ Landroid\/content\/pm\/PackageManager\;\-\>getInstalledApplications\(I\)Ljava\/util\/List\;/) and 
		androguard.functionality.installed_app.method(/a/) and 
		
		androguard.permission("android.permission.GET_TASKS") and 
		androguard.permission("android.permission.INTERNET") and 
		androguard.permission("android.permission.READ_EXTERNAL_STORAGE") and 
		androguard.permission("android.permission.RECEIVE_BOOT_COMPLETED") and 
		androguard.permission("android.permission.WAKE_LOCK") and 
		androguard.permission("android.permission.WRITE_EXTERNAL_STORAGE")
}