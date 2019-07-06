rule wipelocker_a
{
	meta:
		description = "WipeLocker.A"

	strings:
		$a = "Elite has hacked you.Obey or be hacked"
		
	condition:
		$a
}