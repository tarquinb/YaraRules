rule Adflex
{
	meta:
		description = "AdFlex SDK evidences"
		sample = "cae88232c0f929bb67919b98da52ce4ada831adb761438732f45b88ddab26adf"

	strings:
		$1 = "AdFlexSDKService" wide ascii
		$2 = "AdFlexBootUpReceiver" wide ascii
		$3 = "adflex_tracker_source" wide ascii
		$4 = "vn/adflex/sdk/AdFlexSDK" wide ascii

	condition:
		all of them
		
}