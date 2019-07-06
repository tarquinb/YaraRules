rule kemoge : signatures
{
	meta:
		description = "This rule detects kemoge adware using new approach for common code signature generation"
		

	strings:
	$S_12120 = { 12 ?? 39 ?? 08 00 22 ?? ?? ?? 70 10 ?? ?? ?? 00 27 ?? 6e 10 ?? ?? ?? 00 0c ?? 6e 10 ?? ?? ?? 00 0c 01 38 01 0f 00 6e 10 ?? ?? 01 00 0a ?? 33 ?? 09 00 62 ?? ?? ?? 6e 20 ?? ?? ?? 00 0c ?? 11 ?? 6e 10 ?? ?? ?? 00 0a ?? 32 ?? 16 00 6e 10 ?? ?? ?? 00 0c 00 38 00 10 00 6e 10 ?? ?? 00 00 0a ?? 33 ?? 0a 00 62 ?? ?? ?? 6e 20 ?? ?? ?? 00 0c ?? 28 e7 0d ?? 12 ?? 28 e4 }
	$S_3962 = { 39 04 08 00 22 ?? ?? ?? 70 10 ?? ?? ?? 00 27 ?? 12 f0 6e 10 ?? ?? 04 00 0c 01 6e 10 ?? ?? 04 00 0c 02 6e 10 ?? ?? 02 00 0c 02 12 03 6e 30 ?? ?? 21 03 0c 01 52 10 ?? ?? 0f 00 0d 01 28 fe }
	$S_6330 = { 63 00 ?? ?? 38 00 0c 00 12 ?? 60 01 ?? ?? 34 10 07 00 62 00 ?? ?? 71 ?? ?? ?? 20 ?? 0e 00 }
	$S_7120 = { 71 00 ?? ?? 00 00 62 00 ?? ?? 70 10 ?? ?? 00 00 0a 00 0f 00 }
	$S_6326 = { 63 00 ?? ?? 38 00 0a 00 12 ?? 60 01 ?? ?? 34 10 05 00 71 ?? ?? ?? 32 ?? 0e 00 }


	condition:
	3 of them		
}