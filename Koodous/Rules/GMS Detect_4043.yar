import "androguard"
import "file"
import "cuckoo"


rule GMS : jcarneiro
{
	meta:
		description = "This rule detects the usage of Google Mobile Services"

	strings:
		$a = "com.google.android.gms"

	condition:
		$a	
		
}