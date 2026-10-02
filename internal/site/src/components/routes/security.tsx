import { useEffect, useMemo, useRef, useState } from "react"
import { useStore } from "@nanostores/react"
import {
	Area,
	AreaChart,
	Bar,
	BarChart,
	CartesianGrid,
	Cell,
	Pie,
	PieChart,
	Tooltip,
	XAxis,
	YAxis,
	type TooltipProps,
} from "recharts"
import { ArrowDown, ShieldCheck, Server } from "lucide-react"
import { pb } from "@/lib/api"
import { SecurityEventDetail } from "./security-event-detail"
import { $systems } from "@/lib/stores"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import {
	SecurityDatePicker,
	presetRange,
	rangeParams,
	type SecurityDateRange as DateRange,
} from "./security-date-picker"
import { Button } from "@/components/ui/button"
import { ChartContainer } from "@/components/ui/chart"
import { Link, navigate, prependBasePath } from "@/components/router"

type Count = { key: string; count: number }
type Summary = {
	kinds: Count[]
	series: { at: number; kind: string; count: number }[]
	top_ips: Count[]
	top_ports: Count[]
	countries: Count[]
	since: number
	until: number
	step: number
}
type SecurityEvent = {
	id: number
	at: number
	source: string
	kind: string
	peer_ip: string
	client_ip: string
	provenance: string
	host: string
	username: string
	method: string
	path: string
	port: number
	status: number
	country_code: string
}
type Events = { items: SecurityEvent[]; next_before: string }
const kinds: Record<string, { label: string; color: string; badge: string }> = {
	ssh_success: {
		label: "SSH success",
		color: "#10b981",
		badge: "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300",
	},
	ssh_failure: {
		label: "SSH failure",
		color: "#f43f5e",
		badge: "bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300",
	},
	ssh_probe: {
		label: "SSH probe",
		color: "#f59e0b",
		badge: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300",
	},
	firewall_block: {
		label: "Firewall blocks",
		color: "#8b5cf6",
		badge: "bg-violet-100 text-violet-800 dark:bg-violet-950 dark:text-violet-300",
	},
	web_request: {
		label: "Web request",
		color: "#0ea5e9",
		badge: "bg-sky-100 text-sky-800 dark:bg-sky-950 dark:text-sky-300",
	},
	web_probe: {
		label: "Web probe",
		color: "#f97316",
		badge: "bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-300",
	},
}
const panel = "min-w-0 rounded-xl border bg-card p-5 shadow-sm"
const formatNumber = (n: number) => n.toLocaleString("en")
const tooltipStyle = {
	background: "var(--muted)",
	color: "var(--foreground)",
	border: "1px solid var(--border)",
	borderRadius: 10,
}

const countryNames = new Intl.DisplayNames(["en"], { type: "region" })
function countryName(code: string) {
	if (code === "LOCAL") return "Non-public IP"
	if (!/^[A-Z]{2}$/.test(code || "")) return "Unknown"
	return countryNames.of(code) || code
}
function countryFlag(code: string) {
	return /^[A-Z]{2}$/.test(code || "")
		? String.fromCodePoint(...Array.from(code, (letter) => 127397 + letter.charCodeAt(0)))
		: ""
}

export default function Security({ id }: { id?: string }) {
	const systems = useStore($systems)
	const [range, setRange] = useState<DateRange>(() => presetRange("today"))
	return (
		<div className="grid min-w-0 gap-4 pb-12">
			<header className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
				<div className="flex items-center gap-3">
					<ShieldCheck className="size-6 text-sky-600 dark:text-sky-400" />
					<div>
						<h1 className="text-xl font-semibold">Security history</h1>
						<p className="mt-1 text-sm text-muted-foreground">SSH, firewall, and web events.</p>
					</div>
				</div>
				<div className="flex flex-wrap gap-2">
					<SecuritySelect
						label="Choose VPS"
						value={id || ""}
						onValueChange={(value) => navigate(prependBasePath(`/security/${value}`))}
						options={[
							{ value: "", label: "Choose VPS" },
							...systems.map((item) => ({ value: item.id, label: item.name })),
						]}
					/>
					<SecurityDatePicker value={range} onChange={setRange} />
				</div>
			</header>
			{id ? (
				<SecurityView key={`${id}:${range.preset}:${range.from}:${range.to}`} system={id} range={range} />
			) : (
				<div className={panel}>
					<h2 className="mb-2 font-semibold">Choose a VPS to view its history</h2>
					<div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
						{systems.map((item) => (
							<Link
								key={item.id}
								href={prependBasePath(`/security/${item.id}`)}
								className="flex items-center gap-3 rounded-lg border bg-card p-4 hover:bg-accent"
							>
								<Server className="size-5 text-sky-500" />
								{item.name}
							</Link>
						))}
					</div>
				</div>
			)}
		</div>
	)
}

function SecurityView({ system, range }: { system: string; range: DateRange }) {
	const [summary, setSummary] = useState<Summary | null>(null)
	const [error, setError] = useState("")
	const [chartMode, setChartMode] = useState("security")
	useEffect(() => {
		const controller = new AbortController()
		pb.send<Summary>(`/api/beszel/security/summary?${new URLSearchParams({ system, ...rangeParams(range) })}`, {
			signal: controller.signal,
		})
			.then(setSummary)
			.catch((err) => {
				if (!controller.signal.aborted) setError(err.message || "Could not load security history")
			})
		return () => controller.abort()
	}, [system, range])
	const data = useMemo(() => {
		if (!summary) return []
		const rows = new Map<number, Record<string, number>>()
		for (let at = summary.since; at < Math.min(summary.until, Date.now() / 1000); at += summary.step) {
			rows.set(at, { at, ...Object.fromEntries(Object.keys(kinds).map((key) => [key, 0])) })
		}
		for (const row of summary.series) {
			const bucket = rows.get(row.at)
			if (bucket) bucket[row.kind] = row.count
		}
		return Array.from(rows.values())
	}, [summary])
	if (error)
		return (
			<div
				role="alert"
				className="rounded-xl border border-amber-300 bg-amber-50 p-5 text-amber-900 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-200"
			>
				{error}
				<p className="mt-2 text-sm">Check the collector and database configuration for this VPS.</p>
			</div>
		)
	if (!summary)
		return (
			<div role="status" className={`${panel} animate-pulse`}>
				Loading VPS history...
			</div>
		)
	const total = summary.kinds.reduce((sum, row) => sum + row.count, 0)
	const count = (name: string) => summary.kinds.find((row) => row.key === name)?.count || 0
	const successes = count("ssh_success"),
		failures = count("ssh_failure")
	const selectedKinds = Object.keys(kinds).filter(
		(key) => chartMode === "all" || (chartMode === "ssh" ? key.startsWith("ssh_") : key !== "web_request"),
	)
	const timeLabel = (at: number) =>
		new Date(at * 1000).toLocaleString(
			"en",
			summary.step >= 86400
				? { day: "numeric", month: "short" }
				: range.from === range.to
					? { hour: "2-digit", minute: "2-digit" }
					: { day: "numeric", month: "short", hour: "2-digit" },
		)
	const jump = (target: string) => document.getElementById(target)?.focus({ preventScroll: true })
	return (
		<>
			<div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
				{[
					{ name: "total", label: "Total events", count: total, target: "events", color: "#0ea5e9" },
					...["ssh_success", "ssh_failure", "firewall_block"].map((name) => ({
						name,
						label: kinds[name].label,
						count: count(name),
						target: name.startsWith("ssh_") ? name : "events",
						color: kinds[name].color,
					})),
				].map((card) => (
					<a
						key={card.name}
						href={`#${card.target}`}
						onClick={() => jump(card.target)}
						className={`${panel} group transition-shadow hover:shadow-md`}
					>
						<div className="flex items-center justify-between gap-2 text-sm text-muted-foreground">
							{card.label}
							<ArrowDown className="size-4" />
						</div>
						<div className="my-2 text-3xl font-semibold tabular-nums" style={{ color: card.color }}>
							{formatNumber(card.count)}
						</div>
						<span className="text-xs text-muted-foreground group-hover:underline">
							View {card.name === "total" || card.name === "firewall_block" ? "events" : card.label.toLowerCase()} table
						</span>
					</a>
				))}
			</div>
			<div className="grid gap-4 lg:grid-cols-3">
				<section className={`${panel} lg:col-span-2`}>
					<div className="mb-4 flex flex-wrap justify-between gap-3">
						<div>
							<h2 className="font-semibold">Activity over time</h2>
							<p className="text-xs text-muted-foreground">
								{summary.step >= 2592000
									? "30-day totals"
									: summary.step >= 604800
										? "Weekly totals"
										: summary.step >= 86400
											? "Daily totals"
											: "Hourly totals"}
								. Times are local. Hover for details.
							</p>
						</div>
						<SecuritySelect
							label="Chart view"
							value={chartMode}
							onValueChange={setChartMode}
							options={[
								{ value: "security", label: "Security events" },
								{ value: "ssh", label: "SSH only" },
								{ value: "all", label: "All events, including web traffic" },
							]}
						/>
					</div>
					<ChartContainer className="h-72 w-full">
						<AreaChart data={data} margin={{ top: 12, right: 12, left: 0, bottom: 4 }} accessibilityLayer>
							<defs>
								{selectedKinds.map((key) => (
									<linearGradient key={key} id={`security-${key}`} x1="0" y1="0" x2="0" y2="1">
										<stop offset="0%" stopColor={kinds[key].color} stopOpacity={0.4} />
										<stop offset="100%" stopColor={kinds[key].color} stopOpacity={0.03} />
									</linearGradient>
								))}
							</defs>
							<CartesianGrid strokeDasharray="3 3" vertical={false} />
							<XAxis dataKey="at" tickFormatter={timeLabel} minTickGap={48} tickLine={false} axisLine={false} />
							<YAxis allowDecimals={false} width={48} tickLine={false} axisLine={false} />
							<Tooltip
								contentStyle={tooltipStyle}
								labelStyle={{ color: "var(--foreground)" }}
								itemStyle={{ color: "var(--foreground)" }}
								labelFormatter={(value) => new Date(Number(value) * 1000).toLocaleString("en")}
								formatter={(value, name) => [formatNumber(Number(value)), kinds[String(name)]?.label || name]}
							/>
							{selectedKinds.map((key) => (
								<Area
									key={key}
									name={key}
									type="monotone"
									dataKey={key}
									stroke={kinds[key].color}
									fill={`url(#security-${key})`}
									strokeWidth={2}
									isAnimationActive={false}
								/>
							))}
						</AreaChart>
					</ChartContainer>
					<div className="mt-3 flex flex-wrap gap-x-4 gap-y-2 text-xs">
						{selectedKinds.map((key) => (
							<span key={key} className="flex items-center gap-1.5">
								<span className="size-2.5 rounded-full" style={{ background: kinds[key].color }} />
								{kinds[key].label}
							</span>
						))}
					</div>
				</section>
				<section className={panel}>
					<h2 className="font-semibold">Event breakdown</h2>
					<p className="text-xs text-muted-foreground">Share of events within the selected dates</p>
					{total ? (
						<ChartContainer className="h-52 w-full">
							<PieChart accessibilityLayer>
								<Pie
									data={summary.kinds}
									dataKey="count"
									nameKey="key"
									innerRadius="55%"
									outerRadius="80%"
									paddingAngle={2}
									stroke="var(--card)"
									activeShape={{ stroke: "var(--foreground)", strokeWidth: 2, fillOpacity: 1 }}
									isAnimationActive={false}
								>
									{summary.kinds.map((row) => (
										<Cell key={row.key} fill={kinds[row.key]?.color || "#64748b"} />
									))}
								</Pie>
								<Tooltip cursor={false} content={<SecurityPieTooltip />} />
							</PieChart>
						</ChartContainer>
					) : (
						<p className="py-12 text-sm text-muted-foreground">No events recorded</p>
					)}
					<div className="space-y-2 text-sm">
						{summary.kinds.map((row) => (
							<div key={row.key} className="flex items-center gap-2">
								<span className="size-2 rounded-full" style={{ background: kinds[row.key]?.color }} />
								<span>{kinds[row.key]?.label || row.key}</span>
								<span className="ml-auto tabular-nums">{total ? ((row.count / total) * 100).toFixed(1) : 0}%</span>
							</div>
						))}
					</div>
				</section>
				<Ranking
					title="Most active IP addresses"
					description="SSH, web probes, and firewall blocks"
					rows={summary.top_ips}
					color="#0ea5e9"
				/>
				<Ranking
					title="Most blocked ports"
					description="Destination ports blocked by the firewall"
					rows={summary.top_ports}
					color="#8b5cf6"
				/>
				<section className={panel}>
					<h2 className="font-semibold">SSH authentication</h2>
					<p className="mt-1 text-xs text-muted-foreground">Login results within the selected dates</p>
					<div className="my-5 text-4xl font-semibold text-emerald-600 dark:text-emerald-400">
						{successes + failures ? `${((successes / (successes + failures)) * 100).toFixed(1)}%` : "No login attempts"}
					</div>
					<p className="mb-4 text-sm text-muted-foreground">
						Success rate across {formatNumber(successes + failures)} authentication attempts
					</p>
					<div className="flex h-3 overflow-hidden rounded-full bg-muted" aria-hidden="true">
						<div
							className="bg-emerald-500"
							style={{ width: `${(successes / Math.max(1, successes + failures)) * 100}%` }}
						/>
						<div
							className="bg-rose-500"
							style={{ width: `${(failures / Math.max(1, successes + failures)) * 100}%` }}
						/>
					</div>
					<div className="mt-4 flex flex-wrap gap-3 text-sm">
						<a
							className="text-emerald-700 underline dark:text-emerald-300"
							href="#ssh_success"
							onClick={() => jump("ssh_success")}
						>
							Success: {formatNumber(successes)} ↓
						</a>
						<a
							className="text-rose-700 underline dark:text-rose-300"
							href="#ssh_failure"
							onClick={() => jump("ssh_failure")}
						>
							Failure: {formatNumber(failures)} ↓
						</a>
					</div>
				</section>
			</div>
			<Ranking
				title="Countries"
				description="Top 10 estimated sender IP countries across recorded events"
				rows={(summary.countries || []).slice(0, 10).map((row) => ({ ...row, key: countryName(row.key) }))}
				color="#10b981"
			/>
			<EventTable system={system} range={range} fixedKind="ssh_success" title="SSH success" total={successes} />
			<EventTable system={system} range={range} fixedKind="ssh_failure" title="SSH failure" total={failures} />
			<AllEvents system={system} range={range} />
			<p className="text-xs text-muted-foreground">
				All time shows every stored event. Retention is configured on the collector. Probe labels identify suspicious
				patterns and do not confirm a compromise. UFW logging may be rate limited. Visitor IP addresses in older web
				logs cannot be verified. Countries estimate IP locations and may identify a proxy or VPN. Country data from{" "}
				<a href="https://iptoasn.com/" target="_blank" rel="noreferrer" className="underline">
					IPtoASN
				</a>
				.
			</p>
		</>
	)
}

function Ranking({
	title,
	description,
	rows,
	color,
}: {
	title: string
	description: string
	rows: Count[]
	color: string
}) {
	return (
		<section className={panel}>
			<h2 className="font-semibold">{title}</h2>
			<p className="mb-4 text-xs text-muted-foreground">{description}</p>
			{rows.length ? (
				<ChartContainer className="w-full" style={{ height: Math.max(140, rows.length * 30) }}>
					<BarChart data={rows} layout="vertical" margin={{ left: 0, right: 16 }} accessibilityLayer>
						<CartesianGrid horizontal={false} strokeDasharray="3 3" />
						<XAxis type="number" allowDecimals={false} tickLine={false} axisLine={false} />
						<YAxis
							type="category"
							dataKey="key"
							width={130}
							tickFormatter={(value: string) =>
								value.length > 18 ? `${value.slice(0, 10)}…${value.slice(-5)}` : value
							}
							tickLine={false}
							axisLine={false}
							tick={{ fontSize: 11 }}
						/>
						<Tooltip
							contentStyle={tooltipStyle}
							labelStyle={{ color: "var(--foreground)" }}
							itemStyle={{ color: "var(--foreground)" }}
							formatter={(value) => [formatNumber(Number(value)), "Event"]}
							cursor={{ fill: "var(--muted)" }}
						/>
						<Bar dataKey="count" fill={color} radius={[0, 4, 4, 0]} isAnimationActive={false} />
					</BarChart>
				</ChartContainer>
			) : (
				<p className="py-10 text-sm text-muted-foreground">No data recorded</p>
			)}
		</section>
	)
}

function AllEvents({ system, range }: { system: string; range: DateRange }) {
	const [source, setSource] = useState("")
	const [kind, setKind] = useState("")
	return (
		<div className="min-w-0">
			<div className="mb-3 flex flex-wrap gap-2">
				<SecuritySelect
					label="Event source"
					value={source}
					onValueChange={(value) => {
						setSource(value)
						setKind("")
					}}
					options={[
						{ value: "", label: "All sources" },
						{ value: "ssh", label: "SSH" },
						{ value: "firewall", label: "Firewall" },
						{ value: "web", label: "Web" },
					]}
				/>
				<SecuritySelect
					label="Event type"
					value={kind}
					onValueChange={setKind}
					options={[
						{ value: "", label: "All types" },
						...Object.entries(kinds)
							.filter(([key]) => !source || key.startsWith(`${source}_`))
							.map(([value, item]) => ({ value, label: item.label })),
					]}
				/>
			</div>
			<EventTable
				key={`${source}:${kind}`}
				system={system}
				range={range}
				source={source}
				fixedKind={kind}
				anchor="events"
				title="Recent events"
			/>
		</div>
	)
}

function EventTable({
	system,
	range,
	source = "",
	fixedKind = "",
	anchor,
	title,
	total,
}: {
	system: string
	range: DateRange
	source?: string
	fixedKind?: string
	anchor?: string
	title: string
	total?: number
}) {
	const [events, setEvents] = useState<SecurityEvent[]>([])
	const [next, setNext] = useState("")
	const [loading, setLoading] = useState(true)
	const [error, setError] = useState("")
	const requestController = useRef<AbortController | null>(null)
	async function load(before = "") {
		const controller = requestController.current
		if (!controller) return
		setLoading(true)
		setError("")
		try {
			const params = new URLSearchParams({ system, ...rangeParams(range), source, kind: fixedKind, limit: "25" })
			if (before) params.set("before", before)
			const data = await pb.send<Events>(`/api/beszel/security/events?${params}`, {
				signal: controller.signal,
			})
			if (controller.signal.aborted) return
			setEvents((old) => (before ? [...old, ...data.items] : data.items))
			setNext(data.next_before)
		} catch (err) {
			if (!controller.signal.aborted) setError(err instanceof Error ? err.message : "Could not load events")
		} finally {
			if (!controller.signal.aborted) setLoading(false)
		}
	}
	useEffect(() => {
		const controller = new AbortController()
		requestController.current = controller
		void load()
		return () => controller.abort()
	}, [system, range, source, fixedKind])
	return (
		<section
			id={anchor || fixedKind}
			tabIndex={-1}
			className={`${panel} scroll-mt-6 focus-visible:outline-2 focus-visible:outline-ring`}
		>
			<div className="mb-4 flex items-center gap-3">
				<h2 className="font-semibold">{title}</h2>
				{total !== undefined && (
					<span className={`rounded-full px-2.5 py-1 text-xs font-semibold ${kinds[fixedKind].badge}`}>
						{formatNumber(total)} event
					</span>
				)}
				<span className="ml-auto text-xs text-muted-foreground">Newest first</span>
			</div>
			{error && (
				<div role="alert" className="mb-3 text-sm text-rose-600 dark:text-rose-300">
					{error}
					<button className="ml-3 underline" onClick={() => load(events.length ? next : "")}>
						Retry
					</button>
				</div>
			)}
			<p className="mb-3 text-xs text-muted-foreground">
				The source port belongs to the sender. It does not identify the VPS SSH port. SSH command examples are
				illustrations. The original client command is not recorded.
			</p>
			<div className="overflow-x-auto rounded-lg border">
				<table className="w-full text-left text-sm">
					<caption className="sr-only">{title} for this VPS</caption>
					<thead className="bg-muted/60 text-foreground">
						<tr>
							{["Time", "Type", "Sender IP", "Country", "Activity details", "IP address source"].map((name) => (
								<th scope="col" className="whitespace-nowrap px-4 py-3 font-semibold" key={name}>
									{name}
								</th>
							))}
						</tr>
					</thead>
					<tbody>
						{events.map((event) => (
							<tr key={event.id} className="border-t bg-card even:bg-muted/25 hover:bg-muted/60 [&>td]:align-top">
								<td className="whitespace-nowrap px-4 py-3 tabular-nums">
									{new Date(event.at * 1000).toLocaleString("en")}
								</td>
								<td className="whitespace-nowrap px-4 py-3">
									<span
										className={`rounded-full px-2.5 py-1 text-xs font-medium ${kinds[event.kind]?.badge || "bg-muted text-foreground"}`}
									>
										{kinds[event.kind]?.label || event.kind}
									</span>
								</td>
								<td className="whitespace-nowrap px-4 py-3 font-mono text-xs">
									{event.client_ip || event.peer_ip || "Not recorded"}
								</td>
								<td
									className="whitespace-nowrap px-4 py-3 text-xs"
									title="Estimated country of the displayed IP address"
								>
									<span aria-hidden="true">{countryFlag(event.country_code)}</span> {countryName(event.country_code)}
								</td>
								<td className="min-w-72 max-w-md px-4 py-3 align-top text-xs leading-relaxed">
									<SecurityEventDetail event={event} />
								</td>
								<td className="min-w-48 max-w-64 px-4 py-3 align-top text-xs leading-relaxed text-muted-foreground">
									{event.provenance === "cloudflare_validated"
										? "Visitor IP reported by Cloudflare. The proxy address was verified."
										: event.provenance === "legacy_unknown"
											? "IP from an older web log. The original visitor address cannot be verified."
											: event.provenance === "direct_peer"
												? "Connection IP recorded by Nginx. The original visitor address has not been verified."
												: "Source IP recorded directly by the VPS service."}
								</td>
							</tr>
						))}
					</tbody>
				</table>
				{!events.length && (
					<p role="status" className="p-5 text-sm text-muted-foreground">
						{loading
							? "Loading events..."
							: error
								? "Data is unavailable."
								: "No events match these dates and filters."}
					</p>
				)}
			</div>
			{next && (
				<Button variant="outline" className="mt-4" disabled={loading} onClick={() => load(next)}>
					{loading ? "Loading..." : "Load more"}
				</Button>
			)}
		</section>
	)
}

function SecuritySelect({
	label,
	value,
	onValueChange,
	options,
}: {
	label: string
	value: string
	onValueChange: (value: string) => void
	options: { value: string; label: string }[]
}) {
	return (
		<Select value={value || "__all"} onValueChange={(next) => onValueChange(next === "__all" ? "" : next)}>
			<SelectTrigger aria-label={label} className="h-9 w-auto max-w-full min-w-28 gap-3">
				<SelectValue />
			</SelectTrigger>
			<SelectContent>
				{options.map((option) => (
					<SelectItem key={option.value || "__all"} value={option.value || "__all"}>
						{option.label}
					</SelectItem>
				))}
			</SelectContent>
		</Select>
	)
}

function SecurityPieTooltip({ active, payload }: TooltipProps<number, string>) {
	if (!active || !payload?.length) return null
	const item = payload[0]
	const kind = kinds[String(item.name)]
	return (
		<div className="rounded-lg border bg-muted px-3 py-2 text-sm text-foreground shadow-md">
			<div className="flex items-center gap-2">
				<span className="size-2.5 rounded-full" style={{ background: kind?.color || item.color }} />
				<span>{kind?.label || item.name}</span>
				<span className="ml-3 font-semibold tabular-nums">{formatNumber(Number(item.value))}</span>
			</div>
		</div>
	)
}
