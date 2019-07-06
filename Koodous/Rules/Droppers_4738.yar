import "androguard"
import "droidbox"

rule droppers
{
    meta:
        date = "2018-07-21"
        DESCRIPTION = "In progress -- Rule to try to detect droppers"
    strings:
        $a = "pm install"
        $b = /\.apk/
        $c = /install/i
        $d = /\.zip/
        $e = /\.jar/
        $f = "chmod"
    condition:
        droidbox.written.filename(/\.apk/) or droidbox.written.filename(/\.zip/) or droidbox.written.filename(/\.dex/) or droidbox.written.filename(/\.jar/)
        or androguard.activity(/uninstall/i) or androguard.receiver(/uninstall/) or androguard.url(/\.apk/) or androguard.url(/\.zip/) or (androguard.permission(/install_package/i) and ((any of them) or (androguard.activity(/install/i) or androguard.receiver(/install/i))))
}