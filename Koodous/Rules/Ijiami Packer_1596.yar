rule packers : Ijiami
{
	meta:
		description = "This rule detects packers based on files used by them"

	strings:
		$Ijiami_1 = "libexecmain.so"
		$Ijiami_2 = "libexec.so"
		$Ijiami_3 = "ijiami.ajm"
	condition:
		all of them
		
}