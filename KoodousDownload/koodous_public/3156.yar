rule LIAPP
{
	meta:
		description = "LIAPP"
		
    strings:
		$liapp_1 = "LiappClassLoader"
		$liapp_2 = "LIAPPEgg"
		$liapp_3 = "LIAPPClient"
		$liapp_4 = "LIAPPEgg.dex"

	condition:
        any of them 
}