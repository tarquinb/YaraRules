import "androguard"
import "file"
import "cuckoo"


rule banker_R : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
	
		$a3 = "hdfc"nocase
		$a4 = "icici"nocase
		$a5 = "rbl"nocase
		
		$b = "bank"
		
		$c1 = "lockNow"
		$c2 = "setComponentEnabledSetting"
		
		$d = "android.app.action.ADD_DEVICE_ADMIN"

	condition:
	
		(not androguard.certificate.sha1("2EFBFB1F0DEF8663BF4DCAAA8B9AE75DCF083662") or 
		not androguard.certificate.sha1("D58AC412004E6CEDA641A04D3DAF0A0C604CBA55") or
		not androguard.certificate.sha1("FBB61AFF644B046E479FE8B735B6ABB0C0DE8FD7") or 
		not androguard.certificate.sha1("FDD6AD9494F6DC38B19C33E52C812B93BE87442B") or 
		not androguard.certificate.sha1("8555D8923D20F85F601CEFC6F62DC990D4685D67") ) and
		(any of ($a*)) and $b and any of ($c*) and $d
		
}