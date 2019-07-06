import "androguard"
import "file"
import "cuckoo"

rule vpn
{
	
	strings:
		$a = "android.permission.BIND_VPN_SERVICE"

	condition:
		$a 
}