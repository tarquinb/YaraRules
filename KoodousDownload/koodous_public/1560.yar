rule dropper
{
	meta:
		description = "This rule detects a dropper app"
		sample = "6c0216b7c2bffd25a4babb8ba9c502c161b3d02f3fd1a9f72ee806602dd9ba3b"
		sample2 = "0089123af02809d73f299b28869815d4d3a59f04a1cb7173e52165ff03a8456a"
		

	strings:
		$a = "Created-By: Android Gradle 2.0.0"
		$b = "UnKnown0"
		$c = "UnKnown1"
		$d = "Built-By: 2.0.0"
		//$e = "WallpaperService" wide


	condition:
		all of them
}