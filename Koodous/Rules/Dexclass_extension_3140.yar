import "droidbox"



rule dexclass
{
    condition:
        droidbox.read.filename(/dex/) or droidbox.read.filename(/jar/) or droidbox.read.filename(/apk/)  
}