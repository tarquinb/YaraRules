rule Tencent
{
	meta:
		description = "Tencent"
		
    strings:
		$tencent_1 = "TxAppEntry"
		$tencent_2 = "StubShell"
		$tencent_3 = "com.tencent.StubShell.ProxyShell"
		$tencent_4 = "com.tencent.StubShell.ShellHelper"

	condition:
        any of them 
}