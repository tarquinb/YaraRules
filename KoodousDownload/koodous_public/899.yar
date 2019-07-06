rule virus_de_la_policia
{
	meta:
		description = "Virus de la policia"

	strings:
		$a = "ScheduleLockReceiver"
		$b = "AlarmManager"
		$c = "com.android.LockActivity"

	condition:
		all of them
}