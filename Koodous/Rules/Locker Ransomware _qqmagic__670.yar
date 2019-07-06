rule locker_a
{
	meta:
		description = "Locker.A"

	strings:
		$a = "qqmagic"
		
	condition:
		$a
		
}