import "androguard"
import "file"
import "cuckoo"


rule Exobotv2 : abc
{
	meta:
		description = "Exobot payload"
		sample = "a04dee90bbd98cae515c0084acbd18aa91f1de6db28a415c0ac8688286f0acd3"

	condition:

		

		androguard.permission(/REQUEST_IGNORE_BATTERY_OPTIMIZATIONS/) and
		androguard.permission(/SEND_SMS/) and
		androguard.permission(/READ_EXTERNAL_STORAGE/) and
		androguard.permission(/RECEIVE_BOOT_COMPLETED/) and	
		androguard.permission(/READ_PHONE_STATE/) and
		androguard.permission(/READ_CONTACTS/) and
		androguard.permission(/SYSTEM_ALERT_WINDOW/) and
		androguard.permission(/WRITE_SMS/) and	
		androguard.permission(/ACCESS_NETWORK_STATE/) and
		androguard.permission(/RECORD_AUDIO/) and
		androguard.permission(/WAKE_LOCK/) and
		androguard.permission(/GET_TASKS/) and	
		androguard.permission(/CALL_PHONE/) and
		androguard.permission(/RECEIVE_SMS/) and
		androguard.permission(/INTERNET/) and
		androguard.permission(/ACCESS_FINE_LOCATION/) and	
		androguard.permission(/PACKAGE_USAGE_STATS/) and
		androguard.permission(/WRITE_EXTERNAL_STORAGE/) and
		androguard.permission(/READ_SMS/)
		

}
rule RedAlert : abc
{
	meta:
		description = "Redalert payload"
		sample = "ae7082c1f27384fc81a70decd21a48e38230e2c89b66309641a98c37c6847a05"

	condition:

  	androguard.permission(/android.permission.CHANGE_NETWORK_STATE/) and
    androguard.permission(/android.permission.DISABLE_KEYGUARD/) and
    androguard.permission(/android.permission.INTERNET/) and
    androguard.permission(/android.permission.SEND_SMS/) and
    androguard.permission(/android.permission.GET_TASKS/) and
    androguard.permission(/android.permission.WRITE_SMS/) and
    androguard.permission(/android.permission.ACCESS_NETWORK_STATE/) and
    androguard.permission(/android.permission.WAKE_LOCK/) and
    androguard.permission(/android.permission.READ_CALL_LOG/) and
    androguard.permission(/android.permission.BROADCAST_PACKAGE_REMOVED/) and
    androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
    androguard.permission(/android.permission.CALL_PHONE/) and
    androguard.permission(/android.permission.READ_PHONE_STATE/) and
    androguard.permission(/android.permission.READ_SMS/) and
    androguard.permission(/android.permission.VIBRATE/) and
    androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/) and
    androguard.permission(/android.permission.ACCESS_WIFI_STATE/) and
    androguard.permission(/android.permission.RECEIVE_MMS/) and
    androguard.permission(/android.permission.PACKAGE_USAGE_STATS/) and
    androguard.permission(/android.permission.CHANGE_WIFI_STATE/) and
    androguard.permission(/android.permission.RECEIVE_SMS/) and
    androguard.permission(/android.permission.READ_CONTACTS/) 
		

}