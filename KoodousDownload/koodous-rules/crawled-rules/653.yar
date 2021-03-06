
import "androguard"


rule koler : example

{

    meta:

        description = "This rule detects koler rasomware"

        sample = "3c37588cece64fb3010ea92939a3873450dda70693f424d1f332b70677a96137 40cd3009c29f14046336627a9b6e61a1b88f375e2e6ff8d2743a197eb3e2c977"


    strings:

        $string_a = "These privileges are needed to protect your device from attackers, and will prevent Android OS from being destroyed."

        $string_b = "New-York1"

        $string_c = ".dnsbp.cloudns.pro"


    condition:

        ( androguard.package_name("com.android.x5a807058") or

        androguard.activity(/x5a807058/i) or

        any of ($string_*) ) and

        androguard.permission(/com.android.browser.permission.READ_HISTORY_BOOKMARKS/)


}