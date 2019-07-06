rule geohotS4
{
	meta:
		description = "Geohot S4"
		
	strings:
		$a = {7C 44 79 44 20 1C FF F7 B0 EE 20 4B 06 1C 01}

	condition:
		$a
		
}