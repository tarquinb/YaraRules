rule Packer_Qihoo
{
	meta:
		description = "Qihoo 360"
		
    strings:
		$qihoo_1 = "libprotectClass.so"
		$qihoo_2 = "monster.dex"
		$qihoo_3 = "libqupc"
		$qihoo_4 = "com.qihoo.util.StubApplication"
		$qihoo_5 = "com.qihoo.util.DefenceReport"
		$qihoo_6 = "libprotectClass"

	condition:
        any of them 
}