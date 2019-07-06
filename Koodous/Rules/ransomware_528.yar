rule ransomware : svpeng
{
	meta:
		description = "Ransomware"
		in_the_wild = true

	strings:
		$a =  {6e 64 20 79 6f 75 72 27 73 20 64 65 76 69 63 65 20 77 69 6c 6c 20 72 65 62 6f 6f 74 20 61 6e 64}
		$b = "ADD_DEVICE_ADMI"

	condition:
		$a and $b
}