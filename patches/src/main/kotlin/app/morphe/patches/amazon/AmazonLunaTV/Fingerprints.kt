package app.morphe.patches.amazon.AmazonLunaTV

import app.morphe.patcher.Fingerprint
import app.morphe.patcher.string

object CodecUtilsFingerprint : Fingerprint(
    filters = listOf(
        string("adaptive-playback"),
        string("CodecConfig")
    )
)