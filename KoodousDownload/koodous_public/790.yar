import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the fake installers."
		testing = "yes"
		sample = "6e57a0b0b734914da334471ea3cd32b51df52c2d17d5d717935373b18b6e0003" //Fake avast

	condition:
		androguard.activity(/com\.startapp\.android\.publish\.AppWallActivity/) and
		androguard.activity(/com\.startapp\.android\.publish\.list3d\.List3DActivity/)		
		
}