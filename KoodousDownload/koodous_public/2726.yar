import "androguard"
import "file"
import "cuckoo"


rule TriadaDetector
{
	meta:
		description = "Detect Triada"
		

	strings:
		$a = "VF*D^W@#FGF"
		$b ="export LD_LIBRARY_PATH"

	condition:
		$a or $b
		
}