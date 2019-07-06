import "androguard"

rule trojan_smsreg_dropper
{
	meta:
		description = "Trojan Dropper SmsReg"
		sample = "f3527fcd7df9cda83a4abf8647b91c0f2155189730faa6a65f89567a33e3e175"

	strings:
		$a = {77 6F 75 6E 69 70 61 79 73 6D 73}
		$b = {70 61 79 5f 69 6E 66 6F}
		$url1 = "http://tools.8782.net/stat.php"
		$url2 = "www.zhxone.com/service.php"

	condition:
		androguard.permission(/android.permission.DOWNLOAD_WITHOUT_NOTIFICATION/) and
		androguard.permission(/android.permission.SEND_SMS/) and
		all of them 
}