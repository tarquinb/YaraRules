import "androguard"



rule spydealer : trojan
{
	meta:
		description = "This rule detects spydealer trojan"
		report = "https://researchcenter.paloaltonetworks.com/2017/07/unit42-spydealer-android-trojan-spying-40-apps/"
		sample = "4e4a31c89613704bcace4798335e6150b7492c753c95a6683531c2cb7d78b3a2"

	condition:
		androguard.activity(/AndroidserviceActivity/i) and
		androguard.activity(/Camerapic/i) and
		androguard.receiver(/PhoneReceiver/i) and
		androguard.receiver(/NetWorkMonitor/i) and
		androguard.receiver(/TimerReceiver/i) and
		androguard.service(/AaTService/i) and
		androguard.service(/FxService/i) and
		//androguard.service(/InstallApkService/i) and
		androguard.permission("android.permission.CAMERA") and
		androguard.permission("android.permission.GET_ACCOUNTS") and
		androguard.permission("android.permission.INTERNET") and
		androguard.permission("android.permission.RECEIVE_BOOT_COMPLETED") and
		androguard.permission("android.permission.READ_CONTACTS") 
		
		
}