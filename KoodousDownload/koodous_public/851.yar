rule Mapin:trojan
{
	meta:
		description = "Mapin trojan, not droppers"
		sample = "7f208d0acee62712f3fa04b0c2744c671b3a49781959aaf6f72c2c6672d53776"

	strings:
		$a = "138675150963" //GCM id
		$b = "res/xml/device_admin.xml"
		$c = "Device registered: regId ="
		

	condition:
		all of them
		
}