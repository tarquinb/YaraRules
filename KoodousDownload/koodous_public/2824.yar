rule sample

{
	meta:
		description = "sample"
	strings:
		$a = "185.62.188.32"
		$b = "TYPE_SMS_CONTENT"
		$c = "getRunningTasks"

	condition:
		$b and ($a or $c)
}