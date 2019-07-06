import "androguard"
import "file"
import "cuckoo"

rule koodous : SlemBunk_Banker
{
	meta:
		description = "Slembunk_jl"

	strings:
		$a = "slem"
		$b = "185.62.188.32"
		$c = "android.app.extra.DEVICE_ADMIN"
		$d = "telephony/SmsManager"
	
	condition:
		$a and ($b or $c or $d)
		
}