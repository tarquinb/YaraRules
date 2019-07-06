rule DEX38
{
	meta:
		author = "Tom_Sara"
		description = "This rule detects New Dex Format"
		
	strings:
		
		$a = {64 65 78 0a 30 33 38 00}
		
	condition:
		all of them
		
}