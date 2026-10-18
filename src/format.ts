/*
 * On-disk format for a locked note.
 *
 * A locked note remains a valid `.md` file so its title stays visible in the
 * file explorer and it continues to participate in links and the graph. The
 * original file contents (including any of the note's own frontmatter) are
 * encrypted wholesale and embedded in a fenced ```locky (or legacy ```locker) block.
 * A small frontmatter marker plus a human-readable callout sit above it so the file
 * reads sensibly in preview mode and is easy to detect.
 *
 * Layout:
 *
 *   ---
 *   locky: true
 *   locker: true
 *   locky-scope: vault
 *   locker-scope: vault
 *   ---
 *
 *   > [!lock]- Encrypted with Locky
 *   > Run "Locky: Unlock note" (or click the ribbon) to decrypt.
 *
 *   ```locky
 *   {"v":1,...}
 *   ```
 *
 * Robustness notes:
 *  - All detection/parsing normalizes CRLF -> LF first, so notes touched by
 *    Windows editors or sync clients are still recognized (otherwise a user can
 *    be locked out of their own ciphertext).
 *  - Locked-note detection requires the `locky: true` or `locker: true` marker to live in the
 *    file's ACTUAL leading YAML frontmatter (anchored at offset 0), not just
 *    anywhere a `---`/`---` pair happens to appear in the body. This prevents an
 *    ordinary note that merely contains a ```locky example or a thematic-break
 *    block from being misdetected as encrypted.
 */

import type { LockerPayload, LockerScope } from "./crypto";

const FENCE_RE = /```(?:locky|locker)[^\n]*\n([\s\S]*?)\n```/;

/** Collapse CRLF/CR line endings to LF for stable detection and parsing. */
function normalize(content: string): string {
	return content.replace(/\r\n?/g, "\n");
}

/** Extract the file's leading YAML frontmatter block, or null if none. */
function leadingFrontmatter(content: string): string | null {
	const m = normalize(content).match(/^---\n([\s\S]*?)\n---(?:\n|$)/);
	return m ? m[1] : null;
}

export function buildLockedNote(payload: LockerPayload): string {
	const json = JSON.stringify(payload);
	return [
		"---",
		"locky: true",
		"locker: true",
		`locky-scope: ${payload.scope}`,
		`locker-scope: ${payload.scope}`,
		"---",
		"",
		"> [!lock]- 🔒 Encrypted with Locky",
		`> This note is locked${
			payload.scope === "note" ? " with its own password" : ""
		}. Run **Locky: Unlock note** (or click the ribbon lock icon) to decrypt it.`,
		"",
		"```locky",
		json,
		"```",
		"",
	].join("\n");
}

/** Returns true if the file content is a Locky / Lockbox-encrypted note. */
export function isLocked(content: string): boolean {
	const fm = leadingFrontmatter(content);
	if (!fm || !/^(?:locky|locker):\s*true\s*$/m.test(fm)) return false;
	return parseLockedNote(content) !== null;
}

/**
 * Extract the encrypted payload from a locked note. Returns null if the
 * content is not a valid locked note or the payload cannot be parsed.
 */
export function parseLockedNote(content: string): LockerPayload | null {
	const match = normalize(content).match(FENCE_RE);
	if (!match) return null;
	try {
		const payload = JSON.parse(match[1].trim()) as LockerPayload;
		if (
			payload &&
			payload.alg === "AES-GCM" &&
			typeof payload.ct === "string" &&
			payload.ct.length > 0 &&
			typeof payload.salt === "string" &&
			typeof payload.iv === "string"
		) {
			return payload;
		}
		return null;
	} catch {
		return null;
	}
}

/** Best-effort read of the declared scope from the leading frontmatter. */
export function readScope(content: string): LockerScope {
	const fm = leadingFrontmatter(content);
	const m = fm?.match(/^(?:locky|locker)-scope:\s*(vault|note)\s*$/m);
	return m && m[1] === "note" ? "note" : "vault";
}
