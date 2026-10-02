import { useEffect, useMemo, useRef, useState } from "react"
import { useStore } from "@nanostores/react"
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, Tooltip, XAxis, YAxis } from "recharts"
import { ArrowDown, ShieldCheck, Server } from "lucide-react"
import { pb } from "@/lib/api"
import { $systems } from "@/lib/stores"
import { ChartContainer } from "@/components/ui/chart"
import { Link, navigate, prependBasePath } from "@/components/router"

type Count = { key: string; count: number }
type Summary = {
	kinds: Count[]
	series: { at: number; kind: string; count: number }[]
	top_ips: Count[]
	top_ports: Count[]
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
}
type Events = { items: SecurityEvent[]; next_before: string }
type Range = "24h" | "7d" | "30d"
const kinds: Record<string, { label: string; color: string; badge: string }> = {
	ssh_success: {
		label: "SSH berhasil",
		color: "#10b981",
		badge: "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300",
	},
	ssh_failure: {
		label: "SSH gagal",
		color: "#f43f5e",
		badge: "bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300",
	},
	ssh_probe: {
		label: "SSH probe",
		color: "#f59e0b",
		badge: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300",
	},
	firewall_block: {
		label: "Firewall blok",
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
const panel =
	"min-w-0 rounded-xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-700 dark:bg-slate-900/70"
const select = "rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-600 dark:bg-slate-900"
const formatNumber = (n: number) => n.toLocaleString()
const tooltipStyle = {
	background: "var(--background)",
	color: "var(--foreground)",
	border: "1px solid var(--border)",
	borderRadius: 10,
}

export default function Security({ id }: { id?: string }) {
	const systems = useStore($systems)
	const [range, setRange] = useState<Range>("24h")
	const system = systems.find((item) => item.id === id)
	return (
		<div className="grid min-w-0 gap-5 pb-12">
			<header className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-sky-200 bg-sky-50 p-5 dark:border-sky-900 dark:bg-sky-950/40">
				<div className="flex items-center gap-3">
					<ShieldCheck className="size-9 text-sky-600 dark:text-sky-400" />
					<div>
						<h1 className="text-2xl font-semibold">Riwayat Keamanan{system ? ` · ${system.name}` : " VPS"}</h1>
						<p className="mt-1 text-sm text-muted-foreground">
							SSH, firewall, dan web · riwayat per VPS · khusus admin
						</p>
					</div>
				</div>
				<div className="flex flex-wrap gap-2">
					<select
						aria-label="Pilih VPS"
						className={select}
						value={id || ""}
						onChange={(e) => navigate(prependBasePath(`/security/${e.target.value}`))}
					>
						<option value="">Pilih VPS</option>
						{systems.map((item) => (
							<option key={item.id} value={item.id}>
								{item.name}
							</option>
						))}
					</select>
					<select
						aria-label="Rentang waktu"
						className={select}
						value={range}
						onChange={(e) => setRange(e.target.value as Range)}
					>
						<option value="24h">24 jam</option>
						<option value="7d">7 hari</option>
						<option value="30d">30 hari</option>
					</select>
				</div>
			</header>
			{id ? (
				<SecurityView key={`${id}:${range}`} system={id} range={range} />
			) : (
				<div className={panel}>
					<h2 className="mb-2 font-semibold">Pilih VPS untuk melihat riwayatnya</h2>
					<div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
						{systems.map((item) => (
							<Link
								key={item.id}
								href={prependBasePath(`/security/${item.id}`)}
								className="flex items-center gap-3 rounded-lg border border-sky-200 bg-sky-50 p-4 hover:bg-sky-100 dark:border-sky-900 dark:bg-sky-950/40 dark:hover:bg-sky-900/40"
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

function SecurityView({ system, range }: { system: string; range: Range }) {
	const [summary, setSummary] = useState<Summary | null>(null)
	const [error, setError] = useState("")
	const [chartMode, setChartMode] = useState("security")
	useEffect(() => {
		const controller = new AbortController()
		pb.send<Summary>(`/api/beszel/security/summary?${new URLSearchParams({ system, range })}`, {
			signal: controller.signal,
		})
			.then(setSummary)
			.catch((err) => {
				if (!controller.signal.aborted) setError(err.message || "Gagal mengambil riwayat")
			})
		return () => controller.abort()
	}, [system, range])
	const data = useMemo(() => {
		if (!summary) return []
		const rows = new Map<number, Record<string, number>>()
		for (let at = Math.floor(summary.since / summary.step) * summary.step; at <= summary.until; at += summary.step) {
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
				<p className="mt-2 text-sm">Pastikan kolektor dan database security sudah dikonfigurasi untuk VPS ini.</p>
			</div>
		)
	if (!summary)
		return (
			<div role="status" className={`${panel} animate-pulse`}>
				Memuat riwayat VPS…
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
			undefined,
			range === "24h"
				? { hour: "2-digit", minute: "2-digit" }
				: { day: "numeric", month: "short", ...(range === "7d" ? { hour: "2-digit" } : {}) },
		)
	const jump = (target: string) => document.getElementById(target)?.focus({ preventScroll: true })
	return (
		<>
			<div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
				{[
					{ name: "total", label: "Total event", count: total, target: "events", color: "#0ea5e9" },
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
						className={`${panel} group border-t-4 transition-shadow hover:shadow-md`}
						style={{ borderTopColor: card.color }}
					>
						<div className="flex items-center justify-between gap-2 text-sm text-muted-foreground">
							{card.label}
							<ArrowDown className="size-4" />
						</div>
						<div className="my-2 text-3xl font-semibold tabular-nums" style={{ color: card.color }}>
							{formatNumber(card.count)}
						</div>
						<span className="text-xs text-muted-foreground group-hover:underline">
							Lihat tabel {card.name === "total" || card.name === "firewall_block" ? "event" : card.label.toLowerCase()}
						</span>
					</a>
				))}
			</div>
			<div className="grid gap-4 lg:grid-cols-3">
				<section className={`${panel} lg:col-span-2`}>
					<div className="mb-4 flex flex-wrap justify-between gap-3">
						<div>
							<h2 className="font-semibold">Aktivitas dari waktu ke waktu</h2>
							<p className="text-xs text-muted-foreground">
								{range === "30d" ? "Per hari" : "Per jam"} · waktu lokal · arahkan kursor untuk detail
							</p>
						</div>
						<select
							aria-label="Seri grafik"
							className={select}
							value={chartMode}
							onChange={(e) => setChartMode(e.target.value)}
						>
							<option value="security">Event keamanan</option>
							<option value="ssh">SSH saja</option>
							<option value="all">Semua event + web</option>
						</select>
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
								labelFormatter={(value) => new Date(Number(value) * 1000).toLocaleString()}
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
					<h2 className="font-semibold">Komposisi event</h2>
					<p className="text-xs text-muted-foreground">Proporsi pada periode yang dipilih</p>
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
									isAnimationActive={false}
								>
									{summary.kinds.map((row) => (
										<Cell key={row.key} fill={kinds[row.key]?.color || "#64748b"} />
									))}
								</Pie>
								<Tooltip
									contentStyle={tooltipStyle}
									formatter={(value, name) => [formatNumber(Number(value)), kinds[String(name)]?.label || name]}
								/>
							</PieChart>
						</ChartContainer>
					) : (
						<p className="py-12 text-sm text-muted-foreground">Belum ada event</p>
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
					title="IP paling aktif"
					description="SSH, probe web, dan firewall"
					rows={summary.top_ips}
					color="#0ea5e9"
				/>
				<Ranking
					title="Port paling sering diblok"
					description="Tujuan koneksi yang diblok firewall"
					rows={summary.top_ports}
					color="#8b5cf6"
				/>
				<section className={panel}>
					<h2 className="font-semibold">Autentikasi SSH</h2>
					<p className="mt-1 text-xs text-muted-foreground">Hasil login pada periode ini</p>
					<div className="my-5 text-4xl font-semibold text-emerald-600 dark:text-emerald-400">
						{successes + failures ? `${((successes / (successes + failures)) * 100).toFixed(1)}%` : "—"}
					</div>
					<p className="mb-4 text-sm text-muted-foreground">
						Login berhasil dari {formatNumber(successes + failures)} percobaan autentikasi
					</p>
					<div className="flex h-3 overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800" aria-hidden="true">
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
							Berhasil: {formatNumber(successes)} ↓
						</a>
						<a
							className="text-rose-700 underline dark:text-rose-300"
							href="#ssh_failure"
							onClick={() => jump("ssh_failure")}
						>
							Gagal: {formatNumber(failures)} ↓
						</a>
					</div>
				</section>
			</div>
			<EventTable system={system} range={range} fixedKind="ssh_success" title="SSH berhasil" total={successes} />
			<EventTable system={system} range={range} fixedKind="ssh_failure" title="SSH gagal" total={failures} />
			<AllEvents system={system} range={range} />
			<p className="text-xs text-muted-foreground">
				Riwayat tersimpan 30 hari. “Probe” adalah pola mencurigakan, bukan bukti kompromi. Log UFW dapat dibatasi rate
				limit. IP pengunjung pada log web lama tidak dapat diverifikasi.
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
							formatter={(value) => [formatNumber(Number(value)), "Event"]}
							cursor={{ fill: "var(--muted)" }}
						/>
						<Bar dataKey="count" fill={color} radius={[0, 4, 4, 0]} isAnimationActive={false} />
					</BarChart>
				</ChartContainer>
			) : (
				<p className="py-10 text-sm text-muted-foreground">Belum ada data</p>
			)}
		</section>
	)
}

function AllEvents({ system, range }: { system: string; range: Range }) {
	const [source, setSource] = useState("")
	const [kind, setKind] = useState("")
	return (
		<div className="min-w-0">
			<div className="mb-3 flex flex-wrap gap-2">
				<select
					aria-label="Sumber event"
					className={select}
					value={source}
					onChange={(e) => {
						setSource(e.target.value)
						setKind("")
					}}
				>
					<option value="">Semua sumber</option>
					<option value="ssh">SSH</option>
					<option value="firewall">Firewall</option>
					<option value="web">Web</option>
				</select>
				<select aria-label="Jenis event" className={select} value={kind} onChange={(e) => setKind(e.target.value)}>
					<option value="">Semua jenis</option>
					{Object.entries(kinds)
						.filter(([key]) => !source || key.startsWith(`${source}_`))
						.map(([key, item]) => (
							<option key={key} value={key}>
								{item.label}
							</option>
						))}
				</select>
			</div>
			<EventTable
				key={`${source}:${kind}`}
				system={system}
				range={range}
				source={source}
				fixedKind={kind}
				anchor="events"
				title="Event terbaru"
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
	range: Range
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
			const params = new URLSearchParams({ system, range, source, kind: fixedKind, limit: "25" })
			if (before) params.set("before", before)
			const data = await pb.send<Events>(`/api/beszel/security/events?${params}`, {
				signal: controller.signal,
			})
			if (controller.signal.aborted) return
			setEvents((old) => (before ? [...old, ...data.items] : data.items))
			setNext(data.next_before)
		} catch (err) {
			if (!controller.signal.aborted) setError(err instanceof Error ? err.message : "Gagal memuat event")
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
	const ssh = fixedKind === "ssh_success" || fixedKind === "ssh_failure"
	return (
		<section
			id={anchor || fixedKind}
			tabIndex={-1}
			className={`${panel} scroll-mt-6 focus-visible:outline-2 focus-visible:outline-sky-500`}
		>
			<div className="mb-4 flex items-center gap-3">
				<h2 className="font-semibold">{title}</h2>
				{total !== undefined && (
					<span className={`rounded-full px-2.5 py-1 text-xs font-semibold ${kinds[fixedKind].badge}`}>
						{formatNumber(total)} event
					</span>
				)}
				<span className="ml-auto text-xs text-muted-foreground">Terbaru lebih dulu</span>
			</div>
			{error && (
				<div role="alert" className="mb-3 text-sm text-rose-600 dark:text-rose-300">
					{error}
					<button className="ml-3 underline" onClick={() => load(events.length ? next : "")}>
						Coba lagi
					</button>
				</div>
			)}
			<div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-700">
				<table className="w-full text-left text-sm">
					<caption className="sr-only">{title} untuk VPS ini</caption>
					<thead className="bg-sky-50 text-slate-700 dark:bg-slate-800 dark:text-slate-200">
						<tr>
							{["Waktu", "Jenis", "IP", ssh ? "Pengguna" : "Detail", ssh ? "Port klien" : "Asal IP"].map((name) => (
								<th scope="col" className="whitespace-nowrap px-4 py-3 font-semibold" key={name}>
									{name}
								</th>
							))}
						</tr>
					</thead>
					<tbody>
						{events.map((event) => (
							<tr
								key={event.id}
								className="border-t border-slate-200 bg-white even:bg-slate-50 hover:bg-sky-50 dark:border-slate-700 dark:bg-slate-900 dark:even:bg-slate-800/50 dark:hover:bg-slate-800"
							>
								<td className="whitespace-nowrap px-4 py-3 tabular-nums">
									{new Date(event.at * 1000).toLocaleString()}
								</td>
								<td className="whitespace-nowrap px-4 py-3">
									<span
										className={`rounded-full px-2.5 py-1 text-xs font-medium ${kinds[event.kind]?.badge || "bg-slate-100 text-slate-800"}`}
									>
										{kinds[event.kind]?.label || event.kind}
									</span>
								</td>
								<td className="whitespace-nowrap px-4 py-3 font-mono text-xs">
									{event.client_ip || event.peer_ip || "—"}
								</td>
								<td className="min-w-40 max-w-md break-all px-4 py-3 font-mono text-xs">
									{ssh
										? event.username || "—"
										: event.source === "web"
											? `${event.method} ${event.host || ""}${event.path} → ${event.status}`
											: event.source === "ssh"
												? `${event.username || "—"} · port klien ${event.port || "—"}`
												: `port tujuan ${event.port || "—"}`}
								</td>
								<td className="whitespace-nowrap px-4 py-3 text-xs text-muted-foreground">
									{ssh
										? event.port || "—"
										: event.provenance === "cloudflare_validated"
											? "Cloudflare tervalidasi"
											: event.provenance === "legacy_unknown"
												? "Log lama: tidak pasti"
												: "Peer langsung"}
								</td>
							</tr>
						))}
					</tbody>
				</table>
				{!events.length && (
					<p role="status" className="p-5 text-sm text-muted-foreground">
						{loading ? "Memuat event…" : error ? "Data belum tersedia." : "Tidak ada event pada periode ini."}
					</p>
				)}
			</div>
			{next && (
				<button
					className="mt-4 rounded-lg border border-sky-300 bg-sky-50 px-4 py-2 text-sm text-sky-800 disabled:opacity-50 dark:border-sky-800 dark:bg-sky-950 dark:text-sky-200"
					disabled={loading}
					onClick={() => load(next)}
				>
					{loading ? "Memuat…" : "Muat lagi"}
				</button>
			)}
		</section>
	)
}
