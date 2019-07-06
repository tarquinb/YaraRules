
import "androguard"



rule fake_google_chrome

{

    meta:

        description = "This rule detects fake google chrome apps"

        sample = "ac8d89c96e4a7697caee96b7e9de63f36967f889b35b83bb0fa5e6e1568635f5"


    condition:

        androguard.package_name("com.android.chro.me")


}