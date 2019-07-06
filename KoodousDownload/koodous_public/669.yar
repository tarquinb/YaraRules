rule slocker_a
{
	meta:
		description = "SLocker.A"

	strings:
		$a = "StartLockServiceAtBootReceiver"
		$b = "148.251.154.104"
		
	condition:
		$a or $b
		
}