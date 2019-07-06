rule Downloader
{

    strings:
        $a = "res/mipmap-xxhdpi-v4/ic_launcher_antivirus.pngPK"
		$b = "file:///android_asset"
		$c = "market://"
		$d = "MKKSL/x}^<"

    condition:
        all of them
		}