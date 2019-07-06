rule suoji
{
	meta:
		description = "suoji"

	strings:
		$a = "&#x9501;&#x673A;&#x751F;&#x6210;&#x5668;"
		
	condition:
		$a
		
}