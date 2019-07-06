
import "androguard"



rule GhostCtrl 

{

    meta:

        description = "This rule detects partially GhostCtrl campaign"

        sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

        report = "http://blog.trendmicro.com/trendlabs-security-intelligence/android-backdoor-ghostctrl-can-silently-record-your-audio-video-and-more/"



    condition:

        androguard.certificate.sha1("4BB2FAD80003219BABB5C7D30CC8C0DBE40C4D64")



}