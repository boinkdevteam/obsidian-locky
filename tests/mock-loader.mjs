import { statSync } from "node:fs";

export async function resolve(specifier, context, nextResolve) {
	if (specifier === "obsidian") {
		return {
			shortCircuit: true,
			url: new URL("./mocks/obsidian.mjs", import.meta.url).href,
		};
	}

	if (specifier.startsWith("./") || specifier.startsWith("../")) {
		try {
			return await nextResolve(specifier, context);
		} catch (e) {
			if (e.code === "ERR_MODULE_NOT_FOUND") {
				// Try appending .ts
				try {
					return await nextResolve(specifier + ".ts", context);
				} catch {
					return await nextResolve(specifier + "/index.ts", context);
				}
			}
			throw e;
		}
	}

	return nextResolve(specifier, context);
}
