rule diatest
{
strings:
    $ = "/PhoneManager/action/"
    $ = "/uploadPhoneInfoAction"
condition:
    any of them
}