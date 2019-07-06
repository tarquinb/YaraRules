import "cuckoo"


rule Vemnotiba:Adware
{
	meta:
		description = "Android.Spy.305.origin WIP"
		sample = "0e18c6a21c33ecb88b2d77f70ea53b5e23567c4b7894df0c00e70f262b46ff9c"

	/*strings:
		$a = "com.nativemob.client.cloudmessage.CloudMessageService"*/

	condition:
		cuckoo.network.dns_lookup(/client\.api-restlet\.com/) and
		cuckoo.network.dns_lookup(/cloud\.api-restlet\.com/)
}