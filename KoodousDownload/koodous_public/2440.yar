import "androguard"
import "droidbox"


rule TelegramPremiumSMSCampaign
{
	meta:
		description = "This rule detects a campaign spreading applications over Telegram that sends premium SMS messages and subscribes users to these groups to receive daily payed sms"
		sample = "08b1edebe53bef0465d7af37ca551c679f0de2232a4de748b153065e13f0fedd"
	condition:
		droidbox.sendsms("738902") or
		droidbox.sendsms("50501") or
		droidbox.sendsms("50502")
}