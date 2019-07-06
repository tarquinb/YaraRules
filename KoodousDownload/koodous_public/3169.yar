rule DexClassLoader
{
	meta:
		description = "DexClassLoader"

	strings:
		$a = "Ldalvik/system/DexClassLoader;"

	condition:
		$a 
}