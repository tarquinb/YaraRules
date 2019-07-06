import "androguard"

rule android_mazarbot_version_three
{
	meta:
		description = "Yara rule to detect MazarBOT version three"
		family = "Mazarbot"
		sample = "ac2e627f1401659d87975e9e224c868d885129b49dc34c04ff01c90ac29788ef"
		author = "Disane"
	condition:
		androguard.certificate.sha1("219d542f901d8db85c729b0f7ae32410096077cb") and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.RECEIVE_SMS/) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		androguard.permission(/android.permission.GET_TASKS/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.ACCESS_NETWORK_STATE/) and
		androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/) and
		androguard.permission(/android.permission.WAKE_LOCK/) and
		androguard.permission(/android.permission.READ_SMS/) and
		androguard.permission(/android.permission.WRITE_SMS/)
}