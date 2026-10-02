export const webCategories: Record<string, string> = {
	sensitive_files: "Sensitive files",
	wordpress: "WordPress",
	php_tooling: "PHP tooling",
	admin_panels: "Admin panels",
	traversal_injection: "Traversal or injection",
	other_probes: "Other probes",
}
export function authMethodLabel(method?: string) {
	return method === "publickey"
		? "SSH key"
		: method === "password"
			? "Password"
			: method?.startsWith("keyboard-interactive")
				? "Keyboard interactive"
				: "Unavailable"
}
