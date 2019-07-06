rule fbilocker_a
{
	meta:
		description = "FBILocker.A"

	strings:
		$a = "74F6FD5001ED11E4A9DEFABADE999F7A"
		
	condition:
		$a
		
}