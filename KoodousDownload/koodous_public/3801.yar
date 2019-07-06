import "androguard"
import "file"


rule MalignantFeatures : jcarneiro
{
	meta:
		description = "This rule detects the presence of Malignant Features"

	condition:
		androguard.service(/com.app.BestService/)	or
		androguard.activity(/com.app.MainBaseActivity/)	or
		androguard.activity(/com.cie.one.reward.popup.OneRewardPopup/)	or
		androguard.activity(/ContentProviderList_com.adobe.air.CameraUIProvider/)	or
		androguard.activity(/ServiceList_com.sgn.dlc.service.DownloaderService/)	or
		androguard.activity(/UsedPermissionsList_android.permission.DISABLE_KEYGUARD/)	or
		androguard.activity(/ActivityList_com.chartboost.sdk.CBDialogActivity/)	or
		androguard.activity(/ServiceList_com.flymob.sdk.common.server.FlyMobService/)	or
		androguard.activity(/ServiceList_io.mobby.sdk.SyncService/)	or
		androguard.activity(/ServiceList_io.mobby.loader.android.SyncService/)	or
		androguard.activity(/BroadcastReceiverList_io.mobby.loader.android.receiver.SDCardMountedReceiver/)	or
		androguard.activity(/
		/)	or
		androguard.activity(/
		/)	or
		androguard.activity(/
		/)	or
		androguard.activity(/
		/)	or
		androguard.activity(/
		/)	or
		androguard.activity(/
		
}