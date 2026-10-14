package lab.analiti.patches.license

import app.morphe.patcher.extensions.InstructionExtensions.addInstructionsWithLabels
import app.morphe.patcher.extensions.InstructionExtensions.getInstruction
import app.morphe.patcher.extensions.InstructionExtensions.removeInstruction
import app.morphe.patcher.patch.PatchException
import app.morphe.patcher.patch.bytecodePatch
import app.morphe.patcher.util.proxy.mutableTypes.MutableMethod
import app.morphe.patcher.util.smali.ExternalLabel
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.iface.instruction.Instruction
import com.android.tools.smali.dexlib2.iface.instruction.OffsetInstruction
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.iface.reference.StringReference
import lab.analiti.patches.shared.COMPATIBILITY_ANALITI

/**
 * Hides the orange "Sign in" bar that sits under the toolbar on the Speed Test screen.
 *
 * The bar (`@id/globalMessages`) is populated by a single method which also prints an
 * "EXPERT" status line and an upgrade notice, so the view itself cannot simply be
 * removed without losing those. Instead this patch neutralises only the branch that
 * selects the account/sign-in text:
 *
 *     if-eqz  ->  goto
 *
 * Turning that conditional into an unconditional jump reuses a code path that already
 * exists (the one taken when no account state is available), so the register state at
 * the jump target is guaranteed valid. That path immediately recomputes the bar's text
 * length and hides the view when it is empty, which is what makes the bar disappear
 * rather than render blank.
 *
 * This only removes the prompt: the account screen stays reachable from the navigation
 * drawer, and the bar still appears for a genuinely signed-in account.
 */
@Suppress("unused")
val hideSignInBannerPatch = bytecodePatch(
    name = "Hide sign-in banner",
    description = "Removes the orange \"Sign in\" prompt below the toolbar. The account " +
            "screen stays reachable from the drawer.",
    default = true,
) {
    compatibleWith(COMPATIBILITY_ANALITI)

    execute {
        val method = GlobalMessageBarFingerprint.method

        // The sign-in block is guarded by the `if-eqz` preceding the first use of the
        // account action string.
        val anchor = method.indexOfFirstString("action_user_account")
        if (anchor < 0) {
            throw PatchException("Could not locate the account string in the message bar method.")
        }

        var branchIndex = -1
        for (index in anchor downTo 0) {
            if (method.getInstruction<Instruction>(index).opcode == Opcode.IF_EQZ) {
                branchIndex = index
                break
            }
        }
        if (branchIndex < 0) {
            throw PatchException("Could not locate the sign-in guard in the message bar method.")
        }

        // Resolve the branch target. OffsetInstruction reports a *code offset* while the
        // instruction APIs work in *indices*, so translate by accumulating code units.
        val branch = method.getInstruction<OffsetInstruction>(branchIndex)
        val targetIndex = method.indexOfCodeOffset(method.codeOffsetOf(branchIndex) + branch.codeOffset)
        if (targetIndex < 0) {
            throw PatchException("Could not resolve the sign-in guard's branch target.")
        }

        // Insert an unconditional jump over the sign-in block, then drop the original
        // conditional that now sits immediately after it.
        method.addInstructionsWithLabels(
            branchIndex,
            "goto :skipSignIn",
            ExternalLabel("skipSignIn", method.getInstruction(targetIndex)),
        )
        method.removeInstruction(branchIndex + 1)
    }
}

/** Index of the first instruction loading [value] as a string constant, or -1. */
private fun MutableMethod.indexOfFirstString(value: String): Int {
    val instructions = implementation?.instructions ?: return -1
    instructions.forEachIndexed { index, instruction ->
        val reference = (instruction as? ReferenceInstruction)?.reference
        if (reference is StringReference && reference.string == value) return index
    }
    return -1
}

/** Bytecode offset, in code units, of the instruction at [index]. */
private fun MutableMethod.codeOffsetOf(index: Int): Int {
    val instructions = implementation?.instructions
        ?: throw PatchException("Message bar method has no implementation.")
    var offset = 0
    instructions.forEachIndexed { i, instruction ->
        if (i == index) return offset
        offset += instruction.codeUnits
    }
    throw PatchException("Instruction index $index is out of range.")
}

/** Instruction index for the given bytecode [offset], or -1 when there is none. */
private fun MutableMethod.indexOfCodeOffset(offset: Int): Int {
    val instructions = implementation?.instructions ?: return -1
    var current = 0
    instructions.forEachIndexed { i, instruction ->
        if (current == offset) return i
        current += instruction.codeUnits
    }
    return -1
}
