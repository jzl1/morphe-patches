package lab.analiti.patches.license

import app.morphe.patcher.extensions.InstructionExtensions.addInstructions
import app.morphe.patcher.patch.bytecodePatch
import lab.analiti.patches.shared.COMPATIBILITY_ANALITI

/**
 * Removes both client-side licence gates:
 *
 *  1. PairIP's `LicenseClient.checkLicense(Context)` is turned into a no-op, so the
 *     tamper check never runs and the Play Store redirect never happens.
 *  2. The Expert tier predicate is forced to return `true`, so every
 *     expert-only feature (channels/spectrum, iperf3, ...) is unlocked.
 */
@Suppress("unused")
val unlockExpertPatch = bytecodePatch(
    name = "Unlock Expert",
    description = "Unlocks the Expert tier and disables the PairIP licence check.",
    default = true,
) {
    compatibleWith(COMPATIBILITY_ANALITI)

    execute {
        // Void method: return immediately, before the licence check is dispatched.
        LicenseClientCheckFingerprint.method.addInstructions(0, "return-void")

        // Boolean method: return true. The method has no try blocks, so prepending
        // is safe and dexlib2 rewrites the (now unreachable) branch offsets for us.
        ExpertTierFingerprint.method.addInstructions(
            0,
            """
                const/4 v0, 0x1
                return v0
            """.trimIndent(),
        )
    }
}
