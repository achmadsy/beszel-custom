export type EventDetailData = {
	source: string
	kind: string
	username: string
	port: number
	method: string
	host: string
	path: string
	status: number
}

export function SecurityEventDetail({ event }: { event: EventDetailData }) {
	if (event.source === "ssh") {
		const description =
			event.kind === "ssh_success"
				? "SSH login succeeded."
				: event.kind === "ssh_failure"
					? "SSH authentication was rejected."
					: event.username
						? "SSH login attempted with an unrecognized username."
						: "SSH connection closed or negotiation failed."
		// Quote usernames as shell arguments, including names containing apostrophes.
		const username = event.username ? `'${event.username.replaceAll("'", "'\\''")}'` : "USERNAME"
		return (
			<div className="space-y-1">
				<p className="font-medium">{description}</p>
				<p>
					Username:{" "}
					<span className={event.username ? "font-mono" : "text-muted-foreground"}>
						{event.username || "Not recorded for this event"}
					</span>
				</p>
				<p>
					Source port: <span className="tabular-nums">{event.port || "Not recorded for this event"}</span>
				</p>
				<details className="pt-1">
					<summary className="cursor-pointer text-muted-foreground">Example SSH command (illustration)</summary>
					<code className="mt-2 block break-all rounded-md bg-muted px-2 py-1.5">{`ssh -l ${username} VPS_ADDRESS`}</code>
					<p className="mt-2 text-muted-foreground">
						VPS_ADDRESS is the destination server address.
						{!event.username && " USERNAME is a placeholder because the username was not recorded."} This illustrates a
						connection command. The original command used by the sender is not available.
					</p>
				</details>
			</div>
		)
	}
	if (event.source === "web") {
		return (
			<div className="space-y-1">
				<p>
					HTTP method: <span className="font-mono">{event.method || "Not recorded"}</span>
				</p>
				<p>
					Destination host: <span className="break-all font-mono">{event.host || "Not recorded in this log"}</span>
				</p>
				<p>
					Request path: <span className="break-all font-mono">{event.path || "Not recorded"}</span>
				</p>
				<p>
					HTTP status: <span className="tabular-nums">{event.status || "Not recorded"}</span>
				</p>
			</div>
		)
	}
	return (
		<div className="space-y-1">
			<p className="font-medium">Connection blocked by the firewall.</p>
			<p>Blocked destination port: {event.port || "Not recorded for this event"}</p>
		</div>
	)
}
