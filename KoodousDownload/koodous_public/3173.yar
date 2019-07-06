rule DexClassLoader
{
	meta:
		description = "Ldalvik/system/DexClassLoader;"

	strings:
		$a = "Ldalvik/system/DexClassLoader;"

	condition:
		$a 
		
}