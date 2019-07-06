import "androguard"

rule POB_1
{
	meta:
		description = "Detects few POB apps"
		
	condition:
		(androguard.receiver(/android\.app\.admin\.DeviceAdminReceiver/) and
		 androguard.service(/pob\.xyz\.WS/))
		
}