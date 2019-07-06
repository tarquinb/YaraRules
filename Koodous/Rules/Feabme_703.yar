/* Based on: Android/Spy.Feabme.A.
python cromosome.py 
-a apk/f89a3b2c0dd0287a9c0a9d5befbc731da2c2c23befd6c18b72438cff5b153433 
-a apk/8d1c782fae024a7bd31da5429001f28dbad5ba7130998092aebaddcd1112f70b 
-b apk/7fd787871845f34bd52c5b41ba0c457423a00aeb71657ea932f232309d2c7a45 
-b apk/b8b5dc3a68a00f5c549e78d2182dbbf32e370780cfb6e74598ed970b27254717 
-b apk/75283909862faa43e76d0184b9c142259fcd207d3871b55de7dfd50533ccde29 
-b apk/560893bb9c18e194c9b82e11c965b6bd041caf0a11b792b07f5204cf6f2497b5 
-f TinkerAccountLibrary.dll 
*/


rule Feabme : spy
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$string_a = "Android.Hardware.Usb9"
		$string_b = "<PrivateImplementationDetails>{05ec9a1c-bc7f-4614-8c3d-8a1df63a8265}"
		$string_c = "<UrlLogin>k__BackingField"
		$string_d = "txtPassword"
		$string_e = "getFacebook"
		$hex_a = { 23 00 27 00 61 73 73 65 6D 62 6C 69 65 73 2F 54 69 6E 6B 65 72 41 63 63 6F 75 6E 74 4C 69 62 72 61 72 79 2E 64 6C 6C 0A 00 20 }

	condition:
		any of ($string_*) and all of ($hex_*)

		
}