
//https://koodous.com/#/apks/b00a77445af14576cdfbed6739bbb80338893975d3c5ff5d9773e3565a373a30

//https://koodous.com/#/apks/4db562fe69b4baef732eb9969f6b33a77afd9ce31ba5cc7533cf957f43685ce2

//https://koodous.com/#/apks/be12e6699a4c1ad226eb0d0588c996b2cd0c78a72e977ff00d52a27cf623fd05


import "cuckoo"


rule sologame : fakeapps

{

    meta:

        description = "This rule detetcs fake apps"

        sample = "b00a77445af14576cdfbed6739bbb80338893975d3c5ff5d9773e3565a373a30"


    strings:

        $ic = "res/drawable/ic.png"


    condition:


        $ic and cuckoo.network.dns_lookup(/aff.mclick.mobi/)


}