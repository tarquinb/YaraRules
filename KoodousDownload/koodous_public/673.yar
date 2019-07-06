rule simplelocker_a
{
	meta:
		description = "SimpleLocker.A"

	strings:
		$a = "fbi_btn_default"
		
	condition:
		$a
		
}