package app.morphe.patches.amazon.AmazonLunaTV

import app.revanced.patcher.data.BytecodeContext
import app.revanced.patcher.fingerprint.method.impl.MethodFingerprint
import app.revanced.patcher.patch.BytecodePatch
import app.revanced.patcher.patch.annotation.CompatiblePackage
import app.revanced.patcher.patch.annotation.Patch
import app.revanced.patcher.util.smali.addInstructions
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.iface.ClassDef
import com.android.tools.smali.dexlib2.iface.Method as MethodDef
import com.android.tools.smali.dexlib2.iface.instruction.Instruction

/**
 * Fingerprint detecting the hardware verification method
 */
private object DeviceCheckFingerprint : MethodFingerprint(
    returnType = "Z",
    customFingerprint = { methodDef: MethodDef, classDef: ClassDef ->
        methodDef.implementation?.instructions?.any { instruction: Instruction ->
            instruction.opcode == Opcode.CONST_STRING && (
                instruction.toString().contains("Amazon", ignoreCase = true) ||
                instruction.toString().contains("AFT", ignoreCase = true)
            )
        } ?: false
    }
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

        mutableMethod.implementation?.instructions?.clear()
        mutableMethod.addInstructions(
            0,
            """
                const/4 v0, 0x1
                return v0
            """.trimIndent()
        )
    }
}