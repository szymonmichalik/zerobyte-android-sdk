package cloud.zerobyte

/**
 * FCM for the relay's push extension: the registration to send, and the
 * reading of what arrives in `FirebaseMessagingService.onMessageReceived`.
 * Every ZeroByte FCM message is data-only, so the service always runs and the
 * app draws the notification itself after it opens the envelope.
 */
object Fcm {
    private val TOKEN = Regex("^[A-Za-z0-9_:-]{32,1024}$")
    private val TAG = Regex("^[A-Za-z0-9_-]{1,64}$")

    /**
     * A registration for the relay's FCM module. [token] comes from
     * `FirebaseMessaging.getInstance().token`; [tag] comes back in the push, so
     * make it random per link ([PushRegistration.randomTag]): Google sees it.
     */
    @JvmStatic
    @JvmOverloads
    fun registration(token: String, tag: String, alert: String? = null): PushRegistration {
        require(TOKEN.matches(token)) { "token: an FCM registration token" }
        return PushRegistration("fcm", mapOf("token" to token), tag, alert)
    }

    /** The ZeroByte push in `RemoteMessage.data`, or null when the message is not one. */
    @JvmStatic
    fun parse(data: Map<String, String>): FcmPush? {
        val tag = data["zerobyte_tag"]?.takeIf(TAG::matches) ?: return null
        val notify = when (data["zerobyte_notify"]) {
            "alert" -> Notify.ALERT
            "silent" -> Notify.SILENT
            else -> return null
        }
        return FcmPush(tag, notify, if (notify == Notify.ALERT) data["zerobyte_alert"] else null)
    }
}

/**
 * One ZeroByte push: look the link up by [tag], then receive. For
 * [Notify.ALERT], show a notification with what you opened, or with [alert]
 * when the envelope cannot be fetched in time.
 */
data class FcmPush(val tag: String, val notify: Notify, val alert: String?)
