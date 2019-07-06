rule Android_MazarBOT
{
	meta:
		description = "Rule to detect different variants of MazarBOT"
		
	strings:
		$sSignature1 = {0A 68 61 72 64 20 72 65 73 65 74 00}
		$sSignature2 = {16 47 65 74 20 76 69 64 65 6F 20 63 6F 64 65 63 20 61 63 63 65 73 73 00}
		$sSignature3 = {2F 44 65 76 41 64 6D 69 6E 44 69 73 61 62 6C 65 72 3B 00}
		$sSignature4 = {0A 4D 79 57 61 6B 65 4C 6F 63 6B 00}
		$sSignature5 = {2F 4F 76 65 72 6C 61 79 56 69 65 77 3B 00}
		$sSignature6 = {2F 52 65 71 75 65 73 74 46 61 63 74 6F 72 79 3B 00}
		$sSignature7 = {14 67 65 74 41 63 74 69 76 65 50 61 63 6B 61 67 65 50 72 65 4C 00}
		$sSignature8 = {0D 68 69 64 65 53 79 73 44 69 61 6C 6F 67 00}
		$sSignature9 = {0F 69 6E 74 65 72 63 65 70 74 20 73 74 61 72 74 00}
		$sSignature10 = {0B 6C 6F 63 6B 20 73 74 61 74 75 73 00}
		$sSignature11 = {13 6D 61 6B 65 49 6E 63 6F 6D 69 6E 67 4D 65 73 73 61 67 65 00}
		$sSignature12 = {14 6D 61 6B 65 49 6E 74 65 72 63 65 70 74 43 6F 6E 66 69 72 6D 00}
		$sSignature13 = {18 72 65 61 64 4D 65 73 73 61 67 65 73 46 72 6F 6D 44 65 76 69 63 65 44 42 00}
		
		
	condition:
		4 of them
		
}