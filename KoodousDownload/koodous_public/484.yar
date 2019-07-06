rule xbot007
{
	meta:
		source = "https://github.com/maldroid/maldrolyzer/blob/master/plugins/xbot007.py"

	strings:
		$a = "xbot007"

	condition:
		any of them
}