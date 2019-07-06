import "androguard"
import "droidbox"


rule Bankbot_general
{
	meta:
		description = "BankBot general"
		family = "BankBot"

	strings:
		$s1 = "overlayMode" nocase
		$s2 = "disable_forward_calls" nocase
		$s3 = "suggest_text_2_url" nocase
		$s4 = "popupWindow" nocase
		$s5 = "rootId" nocase
		$s6 = "activity_go_adm" nocase
		$s7 = "activity_inj" nocase
		$s8 = "device_admin.xml" nocase
		
		$f1 = "/private/tuk_tuk.php" nocase
		$f2 = "/private/add_log.php" nocase
		$f3 = "/private/set_data.php" nocase
		$f4 = "/set/log_add.php" nocase
		$f5 = "/set/receiver_data.php " nocase
		$f6 = "/set/set.php" nocase
		$f7 = "/set/tsp_tsp.php" nocase		
		
		$cmd1 = "/proc/%d/cmdline" nocase
		$cmd2 = "/proc/%d/cgroup" nocase

		$sms1 = "Sms Is Deleted !" nocase
		$sms2 = "SMS is NOT DELETED" nocase

	condition:
		
		(androguard.url(/37.1.207.31\api\?id=7/) or (androguard.url(/http\:\/\/37\.1\.207/) and (androguard.url(/\/api\/\?id\=7/)) or any of ($s*)) or
		(androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) or androguard.permission(/android.permission.RECEIVE_SMS/) or 		androguard.permission(/android.permission.READ_SMS/) or
		androguard.permission(/android.permission.READ_LOGS/) or androguard.permission(/android.permission.READ_PHONE_STATE/) or androguard.permission(/android.permission.MODIFY_PHONE_STATE/) or
		androguard.permission(/android.permission.QUICKBOOT_POWERON/) or androguard.permission(/android.permission.WRITE_SMS/) or androguard.permission(/android.permission.CALL_PHONE/) or
		androguard.permission(/android.permission.WAKE_LOCK/) or androguard.permission(/android.permission.MODIFY_AUDIO_SETTINGS/) or androguard.permission(/android.permission.GET_TASKS/) or
		androguard.permission(/android.permission.READ_CONTACTS/)) and (androguard.service("*.fyjjnkbfzr") or androguard.service("*.cscxcuooo") or droidbox.read.filename(/com.tvone.untoenynh-1.apk/)) or
		(androguard.activity("*.cnwogedn")or( androguard.receiver("*.lowvuse") and androguard.receiver("*.fzneckm") and androguard.receiver("*.uetxyg")))) or
		(2 of ($f*) and androguard.permission(/android.permission.CALL_PHONE/) and androguard.permission(/android.permission.READ_CONTACTS/) and androguard.permission(/android.permission.READ_PHONE_STATE/)) or 
		(androguard.permission(/android.permission.RECEIVE_SMS/) or androguard.permission(/android.permission.READ_SMS/)) and (2 of ($s*) and 2 of ($f*) and 1 of ($cmd*) and 1 of ($sms*))
}