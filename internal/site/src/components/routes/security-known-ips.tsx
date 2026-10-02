import { useEffect, useState } from "react"
import { pb } from "@/lib/api"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Dialog, DialogContent, DialogDescription, DialogTitle, DialogTrigger } from "@/components/ui/dialog"

type Entry = { network: string; label: string }
export function SecurityKnownIPs({ system, onSaved }: { system: string; onSaved: () => void }) {
	const [open, setOpen] = useState(false)
	const [items, setItems] = useState<Entry[]>([])
	const [loading, setLoading] = useState(false)
	const [ready, setReady] = useState(false)
	const [saving, setSaving] = useState(false)
	const [error, setError] = useState("")
	const endpoint = `/api/beszel/security/known-ips?${new URLSearchParams({ system })}`
	useEffect(() => {
		if (!open) return
		const controller = new AbortController()
		setLoading(true)
		setReady(false)
		setItems([])
		setError("")
		pb.send<{ items: Entry[] }>(endpoint, { signal: controller.signal })
			.then((data) => {
				if (!controller.signal.aborted) {
					setItems(data.items)
					setReady(true)
				}
			})
			.catch((err) => {
				if (!controller.signal.aborted) setError(err.message || "Could not load known IPs")
			})
			.finally(() => {
				if (!controller.signal.aborted) setLoading(false)
			})
		return () => controller.abort()
	}, [open, endpoint])
	async function save() {
		setSaving(true)
		setError("")
		try {
			await pb.send(endpoint, { method: "PUT", body: { items } })
			onSaved()
			setOpen(false)
		} catch (err) {
			setError(err instanceof Error ? err.message : "Could not save known IPs")
		} finally {
			setSaving(false)
		}
	}
	return (
		<Dialog
			open={open}
			onOpenChange={(next) => {
				if (!saving) setOpen(next)
			}}
		>
			<DialogTrigger asChild>
				<Button variant="outline" size="sm">
					Known IPs
				</Button>
			</DialogTrigger>
			<DialogContent className="max-w-xl">
				<DialogTitle>Known IPs for this VPS</DialogTitle>
				<DialogDescription>
					Label addresses you recognize. This list does not allow or block connections. SSH keys do not automatically
					mark an IP as known.
				</DialogDescription>
				{error && (
					<p role="alert" className="text-sm text-rose-600 dark:text-rose-300">
						{error}
					</p>
				)}
				{loading ? (
					<p role="status">Loading known IPs...</p>
				) : (
					<>
						<div className="max-h-[50dvh] space-y-3 overflow-y-auto pr-1">
							{!items.length && <p className="text-sm text-muted-foreground">No known IPs configured.</p>}
							{items.map((item, index) => (
								<fieldset key={index} disabled={saving} className="rounded-lg border p-3">
									<legend className="px-1 text-xs text-muted-foreground">Entry {index + 1}</legend>
									<div className="grid gap-2 sm:grid-cols-2">
										<label className="space-y-1 text-xs">
											IP address or CIDR
											<Input
												aria-label={`IP address ${index + 1}`}
												value={item.network}
												placeholder="203.0.113.10 or 2001:db8::/64"
												maxLength={60}
												onChange={(e) =>
													setItems(items.map((row, i) => (i === index ? { ...row, network: e.target.value } : row)))
												}
											/>
										</label>
										<label className="space-y-1 text-xs">
											Label
											<Input
												aria-label={`IP label ${index + 1}`}
												value={item.label}
												placeholder="Home connection"
												maxLength={80}
												onChange={(e) =>
													setItems(items.map((row, i) => (i === index ? { ...row, label: e.target.value } : row)))
												}
											/>
										</label>
									</div>
									<Button
										variant="ghost"
										size="sm"
										className="mt-2"
										aria-label={`Remove entry ${index + 1}`}
										onClick={() => setItems(items.filter((_, i) => i !== index))}
									>
										Remove
									</Button>
								</fieldset>
							))}
						</div>
						<div className="flex flex-wrap justify-between gap-2">
							<Button
								variant="outline"
								disabled={saving || items.length >= 100 || !ready}
								onClick={() => setItems([...items, { network: "", label: "" }])}
							>
								Add IP
							</Button>
							<Button disabled={saving || !ready} onClick={save}>
								{saving ? "Saving..." : "Save known IPs"}
							</Button>
						</div>
					</>
				)}
			</DialogContent>
		</Dialog>
	)
}
