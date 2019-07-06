import "androguard"

rule wormHole
{
	meta:
		description = "Wormhome vulnerability found in com.qihoo.secstore con GPlay. After app launch, a SimpleWebServer service is called listening to 0.0.0.0:38517. It uses yunpan to upload files and get a 360 domain. App protected by proguard."
	strings: