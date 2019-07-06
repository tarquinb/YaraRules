
//Probably Android.Adware.Mulad


import "androguard"


rule HackedScreen

{

    condition:

        androguard.activity(/.*\.HackedScreen/)

}