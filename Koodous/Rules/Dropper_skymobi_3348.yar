import "androguard"


rule koodous : skymobi
{
	meta:
		source = "https://blog.malwarebytes.org/mobile-2/2015/06/complex-method-of-obfuscation-found-in-dropper-realshell/"
	strings:
		$a = "Java_com_skymobi_pay_common_util_LocalDataDecrpty_Decrypt"
		$b = "Java_com_skymobi_pay_common_util_LocalDataDecrpty_Encrypt"
	
	condition:
		all of them
}