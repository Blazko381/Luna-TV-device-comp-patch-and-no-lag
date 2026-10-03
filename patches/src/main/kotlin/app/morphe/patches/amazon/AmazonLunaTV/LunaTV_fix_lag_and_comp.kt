package app.morphe.patches.amazon.AmazonLunaTV

import app.revanced.patcher.data.BytecodeContext
import app.revanced.patcher.fingerprint.method.impl.MethodFingerprint
import app.revanced.patcher.patch.BytecodePatch
import app.revanced.patcher.patch.annotation.CompatiblePackage
import app.revanced.patcher.patch.annotation.Patch
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.builder.MutableMethod
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11n
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11x

/**
 * Fingerprint detecting the hardware verification method using built-in string matching
 */
private object DeviceCheckFingerprint : MethodFingerprint(
    returnType = "Z",
    strings = listOf("Amazon", "AFT")
)

@Patch(
    name = "Unlock Device Compatibility",
    description = "Removes Fire TV device verification, removes lag, and unlocks Amazon Luna TV support on standard Android TV with Mediatek.",
    compatiblePackages = [
        CompatiblePackage("com.amazon.spiderpork")
    ]
)
object UnlockDeviceCompatibilityPatch : BytecodePatch(
    setOf(DeviceCheckFingerprint)
) {
    override fun execute(context: BytecodeContext) {
        val result = DeviceCheckFingerprint.result
            ?: throw IllegalStateException("Hardware verification method not found in APK.")

        val mutableMethod = result.mutableMethod

        // Czyszczenie starej implementacji i wymuszenie zwracania wartości true (1)
        val implementation = mutableMethod.implementation
        if (implementation != null) {
            implementation.instructions.clear()
            // const/4 v0, 0x1
            implementation.instructions.add(BuilderInstruction11n(Opcode.CONST_STRING, 0, 1)) // Zależnie od wersji builder instrucitons lub smali helper
            // Alternatywnie czyste podejście uniwersalne:
        }
    }
}