import "androguard"
import "droidbox"

rule bankbot_second
{
	meta:
		description = "Banker Catelites"
		family = "Banker"

	condition:
		(androguard.permission(/com.android.launcher.permission.UNINSTALL_SHORTCUT/) and 
		androguard.permission(/android.permission.QUICKBOOT_POWERON/) and
		androguard.permission(/android.permission.INTERNET/) and 
		androguard.permission(/android.permission.SEND_SMS/) and 
		androguard.permission(/com.android.launcher.permission.INSTALL_SHORTCUT/) and
		androguard.permission(/android.permission.WRITE_SMS/) and 
		androguard.permission(/android.permission.GET_TASKS/) and 
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and 
		androguard.permission(/android.permission.CALL_PHONE/) and 
		androguard.permission(/android.permission.READ_SMS/) and
		androguard.permission(/android.permission.VIBRATE/) and
		androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/) and 
		androguard.permission(/android.permission.SEND_RESPOND_VIA_MESSAGE/) and 
		androguard.permission(/android.permission.ACCESS_NOTIFICATION_POLICY/) and
		androguard.permission(/android.permission.KILL_BACKGROUND_PROCESSES/) and 
		androguard.permission(/android.permission.ACCESS_WIFI_STATE/) and 
		androguard.permission(/android.permission.WAKE_LOCK/) and
		androguard.permission(/android.permission.CHANGE_WIFI_STATE/) and 
		androguard.permission(/android.permission.RECEIVE_SMS/) and 
		androguard.permission(/android.permission.READ_CONTACTS/) and
		androguard.permission(/android.permission.GET_ACCOUNTS/)) or
		(droidbox.read.filename("/dev/urandom/") and
		droidbox.written.data("&quot;:&quot;1&quot;}</string>"))

}