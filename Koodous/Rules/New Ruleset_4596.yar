import "androguard"
import "file"
import "cuckoo"


rule Trojan : indianBanker
{

	strings:
		$a = "com.sbi.SBIFreedomPlus"
		$b = "getVoiceMailNumber"
		$c = "banknum"
		$d = "SendTextMessage"
		$e = "removeActiveAdmin"
		$f = "creditcard"
		$g = "Mobilebanking"nocase
		$h = "hdfcbank"
		

	condition:
		all of them
		
}