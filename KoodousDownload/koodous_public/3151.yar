rule Nagapt
{
	meta:
		description = "Nagapt (chaosvmp)"
		
    strings:
		$nagapt_1 = "chaosvmp"
		$nagapt_2 = "ChaosvmpService"

	condition:
        any of them 
}