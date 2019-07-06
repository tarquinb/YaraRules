import "androguard"
import "file"
import "cuckoo"


rule Test7
{
	condition:
		androguard.package_name("com.estrongs.android.pop")
	
}