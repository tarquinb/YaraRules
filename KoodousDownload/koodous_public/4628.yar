import "androguard"

rule aamotest 
{
	meta:
		description = "aamo obfuscator"
		author = "P0r0"
		example = "c1ef860af0e168f924663630ed3b61920b474d0c8b10e2bde6bfd3769dbd31a8"
		example2 = "eb0d4e1ba2e880749594eb8739e65aa21b6f7b43798f04b6681065b396c15a78"
		example3 = "b1e20bf3bdc53972424560e20c6d9ad12e5e47b8ed429a77f4ba5ff6cb92cb27"
		example4 = "82a570c272579aacdc22410e152f4519738f4e0ececa84e016201c33ad871fa6"

	strings:
	$a = { 00 0f 63 6f 6e 76 65 72 74 54 6f 53 74 72 69 6e 67 00 } // convertToString 
	$b = { 00 14 67 65 74 53 74 6f 72 61 67 65 45 6e 63 72 79 70 74 69 6f 6e 00 } //getStorageEncryption

	condition:
		$a and $b
		
}