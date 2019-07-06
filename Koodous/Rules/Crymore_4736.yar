import "androguard"


rule Crymore
{
	meta:
		description = "Cryptocurrency Miner, Crymore"
		packageName = ""
		link1 = "https://drive.google.com/uc?authuser=0&id=183OvtemBaJiP_dPkdCHpcNTjBeTqtP_C&export=download"
		link2 = "https://raw.githubusercontent.com/cryptominesetting/setting/master/Config"
		link3 = "https://raw.githubusercontent.com/cryptominesetting/setting/master/Config2"
		link4 = "https://drive.google.com/uc?authuser=0&id=1nfl9nCCeWkG071NWeOm6fGl8QPvvrtpp&export=download"
	
	strings:
		$a_1 = {68747470733a2f2f64726976652e676f6f676c652e636f6d2f75633f61757468757365723d302669643d3138334f7674656d42614a69505f64506b64434870634e546a4265547174505f43266578706f72743d646f776e6c6f6164}
		$a_2 = {68747470733a2f2f7261772e67697468756275736572636f6e74656e742e636f6d2f63727970746f6d696e6573657474696e672f73657474696e672f6d61737465722f436f6e666967}
		$a_3 = {68747470733a2f2f64726976652e676f6f676c652e636f6d2f75633f61757468757365723d302669643d316e666c396e434365576b473037314e57654f6d3666476c385150767672747070266578706f72743d646f776e6c6f6164}
	condition:
		any of ($a*)
		
}