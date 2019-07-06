import "androguard"
import "file"
import "cuckoo"


rule Exobotv2 : abc
{
	meta:
		description = "Exobot payload abc"
		sample = "a04dee90bbd98cae515c0084acbd18aa91f1de6db28a415c0ac8688286f0acd3"

	condition:
		androguard.permissions_number == 20 and
		androguard.permission(/ACCESS_FINE_LOCATION/) and	
		androguard.permission(/ACCESS_NETWORK_STATE/) and
		androguard.permission(/CALL_PHONE/) and
		androguard.permission(/GET_TASKS/) and	
		androguard.permission(/INTERNET/) and
		androguard.permission(/PACKAGE_USAGE_STATS/) and
		androguard.permission(/READ_CONTACTS/) and
		androguard.permission(/READ_EXTERNAL_STORAGE/) and
		androguard.permission(/READ_PHONE_STATE/) and
		androguard.permission(/READ_SMS/) and
		androguard.permission(/RECEIVE_BOOT_COMPLETED/) and	
		androguard.permission(/RECEIVE_SMS/) and
		androguard.permission(/RECORD_AUDIO/) and
		androguard.permission(/REQUEST_IGNORE_BATTERY_OPTIMIZATIONS/) and
		androguard.permission(/SEND_SMS/) and
		androguard.permission(/SYSTEM_ALERT_WINDOW/) and
		androguard.permission(/WAKE_LOCK/) and
		androguard.permission(/WRITE_EXTERNAL_STORAGE/) and
		androguard.permission(/WRITE_SMS/)
		
}