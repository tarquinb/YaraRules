import "androguard"

rule marcher

{
	meta:
		description = "Marcher"
		family = "Marcher"	
	
	condition:
	
		(androguard.filter("android.intent.action.MAIN") and 
		androguard.filter("android.app.action.ACTION_DEVICE_ADMIN_DISABLE_REQUESTED") and
		androguard.filter("android.app.action.DEVICE_ADMIN_DISABLED") and
		androguard.filter("android.provider.Telephony.SMS_RECEIVED") and
		androguard.filter("MainActivity.AlarmAction") and
		androguard.filter("android.net.conn.CONNECTIVITY_CHANGE") and
		androguard.filter("android.intent.action.BOOT_COMPLETED") and
		androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED") and
		androguard.filter("android.intent.action.QUICKBOOT_POWERON") and
		androguard.filter("android.intent.action.USER_PRESENT"))

			
}