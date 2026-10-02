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
import { Input } from "@/components/ui/input"
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { SecurityKnownIPs } from "./security-known-ips"
import { authMethodLabel, webCategories } from "./security-analysis-labels"
import { SecurityCountryFilter } from "./security-country-filter"
import { SecurityCountryMap } from "./security-country-map"
import { Button } from "@/components/ui/button"
import { ChartContainer } from "@/components/ui/chart"
import { Link, navigate, prependBasePath } from "@/components/router"

type Count = { key: string; count: number }
type EventFilters = { search?: string; category?: string; sshAttempts?: boolean; webProbes?: boolean }
type CollectorStatus = {
	status: string
	started_at?: number
	finished_at?: number
	last_success_at?: number
	oldest_event_at?: number
	newest_event_at?: number
	error?: string
}
type Summary = {
	collector?: CollectorStatus
	top_ssh_ips?: Count[]
	top_usernames?: (Count & { unique_ips: number })[]
	web_categories?: Count[]
	top_web_paths?: Count[]
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
	web_category?: string
	ip_status?: string
	known_ip_label?: string
	prior_failures_24h?: number
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
	const [eventsOpen, setEventsOpen] = useState(false)
	const [eventTab, setEventTab] = useState("events")
	const [chartMode, setChartMode] = useState("security")
	const [revision, setRevision] = useState(0)
	const [insightsOpen, setInsightsOpen] = useState(false)
	const [eventFilters, setEventFilters] = useState<EventFilters>({})
	const [jumpRevision, setJumpRevision] = useState(0)
	useEffect(() => {
		const controller = new AbortController()
		pb.send<Summary>(`/api/beszel/security/summary?${new URLSearchParams({ system, ...rangeParams(range) })}`, {
			signal: controller.signal,
		})
			.then((data) => {
				setSummary(data)
				setError("")
			})
			.catch((err) => {
				if (!controller.signal.aborted) setError(err.message || "Could not load security history")
			})
		return () => controller.abort()
	}, [system, range, revision])
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
	const jump = (target: string, filters: EventFilters = {}) => {
		setEventFilters(filters)
		setJumpRevision((value) => value + 1)
		setEventTab(target)
		setEventsOpen(true)
	}
	return (
		<>
			<section className={`${panel} flex flex-wrap items-center justify-between gap-3`}>
				<div className="min-w-0 space-y-1 text-xs">
					<p
						className={`font-medium ${summary.collector?.status === "failed" || summary.collector?.status === "delayed" ? "text-amber-600 dark:text-amber-300" : "text-muted-foreground"}`}
					>
						{summary.collector?.status === "success"
							? "Collector healthy"
							: summary.collector?.status === "running"
								? "Collection in progress"
								: summary.collector?.status === "failed"
									? "Collection failed"
									: summary.collector?.status === "delayed"
										? "Data delayed"
										: "Collector status unavailable"}
					</p>
					<p className="text-muted-foreground">
						Last collected:{" "}
						{summary.collector?.last_success_at
							? new Date(summary.collector.last_success_at * 1000).toLocaleString("en")
							: "Unavailable"}
					</p>
					{summary.collector?.oldest_event_at && (
						<p className="text-muted-foreground">
							Stored history: {new Date(summary.collector.oldest_event_at * 1000).toLocaleDateString("en")} to{" "}
							{new Date(
								(summary.collector.newest_event_at || summary.collector.oldest_event_at) * 1000,
							).toLocaleDateString("en")}
						</p>
					)}
					{summary.collector?.error && (
						<p className="text-muted-foreground">Error: {summary.collector.error}. Check the collector journal.</p>
					)}
				</div>
				<div className="flex gap-2">
					<SecurityKnownIPs system={system} onSaved={() => setRevision((value) => value + 1)} />
					<Button variant="outline" size="sm" onClick={() => setRevision((value) => value + 1)}>
						Refresh status
					</Button>
				</div>
			</section>
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
					<button
						key={card.name}
						type="button"
						onClick={() => jump(card.target)}
						className={`${panel} text-left group transition-shadow hover:shadow-md`}
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
					</button>
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
					<ChartContainer className="h-72 w-full overflow-hidden">
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
						<ChartContainer className="h-52 w-full overflow-hidden">
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
						<button
							className="text-emerald-700 underline dark:text-emerald-300"
							type="button"
							onClick={() => jump("ssh_success")}
						>
							Success: {formatNumber(successes)} ↓
						</button>
						<button
							className="text-rose-700 underline dark:text-rose-300"
							type="button"
							onClick={() => jump("ssh_failure")}
						>
							Failure: {formatNumber(failures)} ↓
						</button>
					</div>
				</section>
			</div>
			<section className={panel}>
				<div className="flex flex-wrap items-center justify-between gap-2">
					<div>
						<h2 className="font-semibold">SSH and web insights</h2>
						<p className="text-xs text-muted-foreground">
							Attempted usernames, SSH sources, and probe categories within the selected dates.
						</p>
					</div>
					<Button
						variant="outline"
						size="sm"
						aria-expanded={insightsOpen}
						aria-controls="security-insights"
						onClick={() => setInsightsOpen(!insightsOpen)}
					>
						{insightsOpen ? "Hide insights" : "Show insights"}
					</Button>
				</div>
				{insightsOpen && (
					<div id="security-insights" className="mt-4 grid gap-4 lg:grid-cols-2">
						<Ranking
							title="Most attempted usernames"
							description="SSH failures and probes. Select a username to inspect attempts."
							rows={summary.top_usernames || []}
							color="#f43f5e"
							onSelect={(key) => jump("events", { search: key, sshAttempts: true })}
						/>
						<Ranking
							title="SSH attempt sources"
							description="SSH failures and probes, excluding successful logins."
							rows={summary.top_ssh_ips || []}
							color="#f97316"
							onSelect={(key) => jump("events", { search: key, sshAttempts: true })}
						/>
						<Ranking
							title="Web probe categories"
							description="Patterns in recorded requests, not confirmed exploits."
							rows={summary.web_categories || []}
							color="#8b5cf6"
							label={(key) => webCategories[key] || key}
							onSelect={(category) => jump("events", { category })}
						/>
						<Ranking
							title="Most probed paths"
							description="Query strings removed and token-like path segments masked."
							rows={summary.top_web_paths || []}
							color="#0ea5e9"
							onSelect={(key) => jump("events", { search: key, webProbes: true })}
						/>
					</div>
				)}
			</section>
			<SecurityCountryMap rows={summary.countries || []} />
			<section className={`${panel} flex flex-wrap items-center justify-between gap-3`}>
				<div>
					<h2 className="font-semibold">Event explorer</h2>
					<p className="text-xs text-muted-foreground">Search and inspect recorded activity.</p>
				</div>
				<div className="flex flex-wrap gap-2">
					<Button variant="outline" size="sm" onClick={() => jump("ssh_success")}>
						SSH success
					</Button>
					<Button variant="outline" size="sm" onClick={() => jump("ssh_failure")}>
						SSH failure
					</Button>
					<Button size="sm" onClick={() => jump("events")}>
						Browse events
					</Button>
				</div>
			</section>
			<Dialog open={eventsOpen} onOpenChange={setEventsOpen}>
				<DialogContent
					className="flex h-[88dvh] w-[calc(100%-2rem)] max-w-7xl flex-col gap-3 overflow-hidden rounded-lg p-4 sm:p-6"
					onOpenAutoFocus={(event) => {
						event.preventDefault()
						requestAnimationFrame(() => document.querySelector<HTMLInputElement>("[data-security-search]")?.focus())
					}}
				>
					<DialogTitle>Event explorer</DialogTitle>
					<DialogDescription>Events for the VPS and date range selected on the dashboard.</DialogDescription>
					<Tabs value={eventTab} onValueChange={setEventTab} className="flex min-h-0 min-w-0 flex-1 flex-col">
						<TabsList aria-label="Event tables" className="grid w-full shrink-0 grid-cols-3">
							<TabsTrigger value="events" className="px-1 text-xs sm:text-sm">
								Recent events
							</TabsTrigger>
							<TabsTrigger value="ssh_success" className="gap-1 px-1 text-xs sm:text-sm">
								SSH success{" "}
								<span className="hidden text-emerald-600 dark:text-emerald-400 sm:inline">
									{formatNumber(successes)}
								</span>
							</TabsTrigger>
							<TabsTrigger value="ssh_failure" className="gap-1 px-1 text-xs sm:text-sm">
								SSH failure{" "}
								<span className="hidden text-rose-600 dark:text-rose-400 sm:inline">{formatNumber(failures)}</span>
							</TabsTrigger>
						</TabsList>
						<TabsContent value="events" className="min-h-0 flex-1 overflow-y-auto">
							<AllEvents
								key={`${revision}:${jumpRevision}`}
								system={system}
								range={range}
								countries={summary.countries || []}
								initialFilters={eventFilters}
							/>
						</TabsContent>
						<TabsContent value="ssh_success" className="min-h-0 flex-1 overflow-y-auto">
							<EventTable
								system={system}
								range={range}
								key={`success:${revision}:${jumpRevision}`}
								fixedKind="ssh_success"
								title="SSH success"
								total={successes}
								countries={summary.countries || []}
							/>
						</TabsContent>
						<TabsContent value="ssh_failure" className="min-h-0 flex-1 overflow-y-auto">
							<EventTable
								system={system}
								range={range}
								key={`failure:${revision}:${jumpRevision}`}
								fixedKind="ssh_failure"
								title="SSH failure"
								total={failures}
								countries={summary.countries || []}
							/>
						</TabsContent>
					</Tabs>
				</DialogContent>
			</Dialog>

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
	onSelect,
	label = (key) => key,
}: {
	title: string
	description: string
	rows: Count[]
	color: string
	onSelect?: (key: string) => void
	label?: (key: string) => string
}) {
	return (
		<section className={panel}>
			<h2 className="font-semibold">{title}</h2>
			<p className="mb-4 text-xs text-muted-foreground">{description}</p>
			{rows.length ? (
				<ChartContainer className="w-full overflow-hidden" style={{ height: Math.max(140, rows.length * 30) }}>
					<BarChart
						data={rows.map((row) => ({ ...row, label: label(row.key) }))}
						layout="vertical"
						margin={{ left: 0, right: 16 }}
						accessibilityLayer
					>
						<CartesianGrid horizontal={false} strokeDasharray="3 3" />
						<XAxis type="number" allowDecimals={false} tickLine={false} axisLine={false} />
						<YAxis
							type="category"
							dataKey="label"
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
						<Bar
							dataKey="count"
							fill={color}
							radius={[0, 4, 4, 0]}
							isAnimationActive={false}
							onClick={(row) => onSelect?.(row.key)}
							cursor={onSelect ? "pointer" : undefined}
						/>
					</BarChart>
				</ChartContainer>
			) : (
				<p className="py-10 text-sm text-muted-foreground">No data recorded</p>
			)}
			{onSelect && !!rows.length && (
				<div className="mt-3 flex flex-wrap gap-2">
					{rows.map((row) => (
						<button
							type="button"
							key={row.key}
							onClick={() => onSelect(row.key)}
							className="rounded-md border px-2 py-1 text-left text-xs hover:bg-muted"
						>
							{label(row.key)}: {formatNumber(row.count)}
							{"unique_ips" in row ? ` from ${Number(row.unique_ips)} unique IPs` : ""}
						</button>
					))}
				</div>
			)}
		</section>
	)
}

function AllEvents({
	system,
	range,
	countries,
	initialFilters = {},
}: {
	system: string
	range: DateRange
	countries: Count[]
	initialFilters?: EventFilters
}) {
	const [source, setSource] = useState(
		initialFilters.category || initialFilters.webProbes ? "web" : initialFilters.sshAttempts ? "ssh" : "",
	)
	const [kind, setKind] = useState(initialFilters.category || initialFilters.webProbes ? "web_probe" : "")
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
				system={system}
				range={range}
				source={source}
				fixedKind={kind}
				anchor="events"
				initialFilters={initialFilters}
				countries={countries}
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
	countries,
	initialFilters = {},
}: {
	system: string
	range: DateRange
	source?: string
	fixedKind?: string
	anchor?: string
	title: string
	total?: number
	countries: Count[]
	initialFilters?: EventFilters
}) {
	const [events, setEvents] = useState<SecurityEvent[]>([])
	const [next, setNext] = useState("")
	const [page, setPage] = useState(0)
	const [cursors, setCursors] = useState([""])
	const [pageSize, setPageSize] = useState("10")
	const [search, setSearch] = useState(initialFilters.search || "")
	const [query, setQuery] = useState(initialFilters.search || "")
	const [country, setCountry] = useState("")
	const [ipStatus, setIPStatus] = useState("")
	const [authMethod, setAuthMethod] = useState("")
	const [category, setCategory] = useState(initialFilters.category || "")
	const [sshAttempts, setSSHAttempts] = useState(initialFilters.sshAttempts || false)
	const filtered = !!(query || country || ipStatus || authMethod || category || sshAttempts)
	useEffect(() => {
		const timer = setTimeout(() => setQuery(search.trim()), 300)
		return () => clearTimeout(timer)
	}, [search])
	useEffect(() => {
		if ((source && source !== "ssh") || (fixedKind && !fixedKind.startsWith("ssh_"))) {
			setIPStatus("")
			setAuthMethod("")
			setSSHAttempts(false)
		}
		if ((source && source !== "web") || (fixedKind && !fixedKind.startsWith("web_"))) setCategory("")
		if (fixedKind && fixedKind !== "ssh_success") setIPStatus("")
	}, [source, fixedKind])
	const [loading, setLoading] = useState(true)
	const [error, setError] = useState("")
	const requestController = useRef<AbortController | null>(null)
	const lastRequest = useRef({ before: "", page: 0 })
	async function load(before = "", targetPage = 0) {
		const controller = requestController.current
		if (!controller) return
		lastRequest.current = { before, page: targetPage }
		setLoading(true)
		setError("")
		try {
			const params = new URLSearchParams({
				system,
				...rangeParams(range),
				source,
				kind: fixedKind,
				limit: pageSize,
				q: query,
				country,
				ip_status: ipStatus,
				auth_method: authMethod,
				web_category: category,
				ssh_attempts: sshAttempts ? "true" : "",
			})
			if (before) params.set("before", before)
			const data = await pb.send<Events>(`/api/beszel/security/events?${params}`, {
				signal: controller.signal,
			})
			if (controller.signal.aborted) return
			setEvents(data.items)
			setPage(targetPage)
			setCursors((old) => {
				const updated = old.slice(0, targetPage + 1)
				updated[targetPage] = before
				return updated
			})
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
		setEvents([])
		setPage(0)
		setCursors([""])
		void load()
		return () => controller.abort()
	}, [system, range, source, fixedKind, query, pageSize, country, ipStatus, authMethod, category, sshAttempts])
	return (
		<section
			id={anchor || fixedKind}
			tabIndex={-1}
			className="min-w-0 focus-visible:outline-2 focus-visible:outline-ring"
		>
			<div className="mb-4 flex items-center gap-3">
				<h2 className="font-semibold">{title}</h2>
				{total !== undefined && !filtered && (
					<span className={`rounded-full px-2.5 py-1 text-xs font-semibold ${kinds[fixedKind].badge}`}>
						{formatNumber(total)} {total === 1 ? "event" : "events"}
					</span>
				)}
				<span className="ml-auto text-xs text-muted-foreground">Newest first</span>
			</div>
			{error && (
				<div role="alert" className="mb-3 text-sm text-rose-600 dark:text-rose-300">
					{error}
					<button className="ml-3 underline" onClick={() => load(lastRequest.current.before, lastRequest.current.page)}>
						Retry
					</button>
				</div>
			)}
			<div className="mb-3 flex flex-wrap items-center gap-2">
				<Input
					data-security-search
					aria-label="Search events"
					maxLength={200}
					placeholder="Search IP, username, or path"
					value={search}
					onChange={(event) => setSearch(event.target.value)}
					className="h-9 min-w-40 flex-1"
				/>
				<SecurityCountryFilter value={country} onChange={setCountry} countries={countries} />
				<SecuritySelect
					label="Rows per page"
					value={pageSize}
					onValueChange={setPageSize}
					options={[10, 25, 50].map((size) => ({ value: String(size), label: `${size} rows` }))}
				/>
			</div>
			<div className="mb-3 flex flex-wrap gap-2">
				{(!source || source === "ssh") && (!fixedKind || fixedKind.startsWith("ssh_")) && (
					<>
						{(!fixedKind || fixedKind === "ssh_success") && (
							<SecuritySelect
								label="Login IP status"
								value={ipStatus}
								onValueChange={setIPStatus}
								options={[
									{ value: "", label: "All login IPs" },
									{ value: "known", label: "Known IP" },
									{ value: "unrecognized", label: "Unrecognized IP" },
								]}
							/>
						)}
						<SecuritySelect
							label="Authentication method"
							value={authMethod}
							onValueChange={setAuthMethod}
							options={[
								{ value: "", label: "All auth methods" },
								{ value: "publickey", label: "SSH key" },
								{ value: "password", label: "Password" },
								{ value: "keyboard-interactive", label: "Keyboard interactive" },
								{ value: "unavailable", label: "Unavailable" },
							]}
						/>
					</>
				)}
				{(!source || source === "web") && (!fixedKind || fixedKind.startsWith("web_")) && (
					<SecuritySelect
						label="Web probe category"
						value={category}
						onValueChange={setCategory}
						options={[
							{ value: "", label: "All probe categories" },
							...Object.entries(webCategories).map(([value, label]) => ({ value, label })),
						]}
					/>
				)}
				{sshAttempts && (
					<Button variant="outline" size="sm" onClick={() => setSSHAttempts(false)}>
						SSH attempts only: clear
					</Button>
				)}
				{filtered && (
					<Button
						variant="ghost"
						size="sm"
						onClick={() => {
							setSearch("")
							setQuery("")
							setCountry("")
							setIPStatus("")
							setAuthMethod("")
							setCategory("")
							setSSHAttempts(false)
						}}
					>
						Clear table filters
					</Button>
				)}
			</div>

			<div
				aria-busy={loading}
				className={`max-h-[50dvh] overflow-auto rounded-lg border ${loading && events.length ? "opacity-60" : ""}`}
			>
				<table className="w-full text-left text-sm">
					<caption className="sr-only">{title} for this VPS</caption>
					<thead className="sticky top-0 z-10 bg-muted text-foreground">
						<tr>
							{["Time", "Type", "Sender IP", "Country", "Activity", "Details"].map((name) => (
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
								<td className="min-w-48 max-w-72 px-4 py-3 text-xs">
									{event.source === "ssh"
										? event.username
											? `User: ${event.username}`
											: "Username not recorded"
										: event.source === "web"
											? `${event.method || "HTTP"} ${event.path || "Path not recorded"}`
											: `Destination port: ${event.port || "Not recorded"}`}
									{event.kind === "ssh_success" && (
										<div className="mt-1 space-y-1">
											<p
												className={
													event.ip_status === "known"
														? "text-emerald-600 dark:text-emerald-300"
														: "text-amber-600 dark:text-amber-300"
												}
											>
												{event.ip_status === "known"
													? `Known IP${event.known_ip_label ? `: ${event.known_ip_label}` : ""}`
													: "Unrecognized IP"}
											</p>
											<p className="text-muted-foreground">{authMethodLabel(event.method)}</p>
											{!!event.prior_failures_24h && (
												<p className="text-amber-600 dark:text-amber-300">
													{formatNumber(event.prior_failures_24h)} failures from this IP in the preceding 24 hours
												</p>
											)}
										</div>
									)}
									{event.web_category && (
										<p className="mt-1 text-violet-600 dark:text-violet-300">
											{webCategories[event.web_category] || event.web_category}
										</p>
									)}
								</td>
								<td className="min-w-40 px-4 py-3 text-xs">
									<details>
										<summary className="cursor-pointer whitespace-nowrap text-muted-foreground">View details</summary>
										<div className="mt-2 w-72 max-w-[70vw] space-y-3 leading-relaxed">
											<SecurityEventDetail event={event} />
											<p className="text-muted-foreground">
												IP address source:{" "}
												{event.provenance === "cloudflare_validated"
													? "Visitor IP reported by Cloudflare. The proxy address was verified."
													: event.provenance === "legacy_unknown"
														? "IP from an older web log. The original visitor address cannot be verified."
														: event.provenance === "direct_peer"
															? "Connection IP recorded by Nginx. The original visitor address has not been verified."
															: "Source IP recorded directly by the VPS service."}
											</p>
										</div>
									</details>
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
			<div
				className="mt-3 flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground"
				aria-live="polite"
			>
				<span>
					{loading
						? "Loading events..."
						: events.length
							? `Rows ${page * Number(pageSize) + 1} to ${page * Number(pageSize) + events.length}`
							: "0 rows"}
					{total !== undefined && !filtered ? ` of ${formatNumber(total)} ${total === 1 ? "event" : "events"}` : ""}
				</span>
				<div className="flex items-center gap-2">
					<Button
						variant="outline"
						size="sm"
						disabled={loading || page === 0}
						onClick={() => load(cursors[page - 1], page - 1)}
					>
						Previous
					</Button>
					<span>Page {page + 1}</span>
					<Button variant="outline" size="sm" disabled={loading || !next} onClick={() => load(next, page + 1)}>
						Next
					</Button>
				</div>
			</div>
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
