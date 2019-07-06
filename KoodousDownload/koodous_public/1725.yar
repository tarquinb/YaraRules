import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "Adware showing full-screen ads even if infected app is closed"
		sample = "0e18c6a21c33ecb88b2d77f70ea53b5e23567c4b7894df0c00e70f262b46ff9c"
		ref_link = "http://news.drweb.com/show/?i=10115&c=38&lng=en&p=0"

	strings:
		$a = "com/nativemob/client/" // Ad-network library

	condition:
		all of them
		
}