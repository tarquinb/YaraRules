import "androguard"


rule Android_Tordow
{
	meta:
		description = "Trojan-Banker.AndroidOS.Tordow."
		source = "https://securelist.com/blog/mobile/76101/the-banker-that-can-steal-anything/"

	strings:
		$dropperA = {41 50 49 32 53 65 72 76 69 63 65}
		$dropperB = {64 69 32 2F 74 77 6F}
		$dropperC = {43 72 79 70 74 6F 55 74 69 6C}
		
		$droppedA = {72 61 63 63 6F 6F 6E}
		$droppedB = {50 52 49 56 41 54 45 5F 43 41 43 48 45}
		$droppedC = {63 6F 6E 74 65 6E 74 3A 2F 2F 73 6D 73 2F}
		$droppedD = {53 6D 73 4F 62 73 65 72 76 65 72}
	
		
	condition:

		( $dropperA and $dropperB and $dropperC ) or
		( $droppedA and $droppedB and $droppedC and $droppedD )
		
}