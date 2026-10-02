import { useState } from "react"
import regions from "./security-map/countries.json"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"

type Count = { key: string; count: number }
const names = new Intl.DisplayNames(["en"], { type: "region" })
const name = (code: string) =>
	/^[A-Z]{2}$/.test(code) ? names.of(code) || code : code === "LOCAL" ? "Non-public IP" : "Unknown"
const number = (value: number) => value.toLocaleString("en")

export function SecurityCountryMap({ rows }: { rows: Count[] }) {
	const countries = rows.filter((row) => /^[A-Z]{2}$/.test(row.key))
	const options = Array.from(
		new Set([...regions.map((region) => region.code), ...countries.map((row) => row.key)]),
	).sort((a, b) => name(a).localeCompare(name(b)))
	const counts = new Map(rows.map((row) => [row.key, row.count]))
	const [selected, setSelected] = useState(countries[0]?.key || "US")
	const [hovered, setHovered] = useState("")
	const active = hovered || selected
	const total = rows.reduce((sum, row) => sum + row.count, 0)
	const maximum = Math.max(1, ...countries.map((row) => row.count))
	const count = counts.get(active) || 0
	const unknown = rows.filter((row) => !/^[A-Z]{2}$/.test(row.key)).reduce((sum, row) => sum + row.count, 0)
	const color = (value: number) =>
		value ? `hsl(160 65% ${80 - (48 * Math.log1p(value)) / Math.log1p(maximum)}%)` : "var(--muted)"
	return (
		<section className="min-w-0 rounded-xl border bg-card p-5 shadow-sm">
			<div className="mb-3 flex flex-wrap items-start justify-between gap-3">
				<div>
					<h2 className="font-semibold">Countries</h2>
					<p className="text-xs text-muted-foreground">Recorded events by estimated sender IP country</p>
				</div>
				{countries.length > 0 && (
					<Select value={selected} onValueChange={setSelected}>
						<SelectTrigger aria-label="Explore country" className="h-9 w-auto max-w-full gap-3">
							<SelectValue />
						</SelectTrigger>
						<SelectContent>
							{options.map((code) => (
								<SelectItem key={code} value={code}>
									{name(code)}
								</SelectItem>
							))}
						</SelectContent>
					</Select>
				)}
			</div>
			<div className="grid items-center gap-4 lg:grid-cols-[minmax(0,1fr)_13rem]">
				<svg
					viewBox="0 0 1080 435"
					role="img"
					aria-label="World map of event countries. Use arrow keys to explore countries."
					tabIndex={0}
					className="w-full rounded-lg bg-muted/20 focus-visible:outline-2 focus-visible:outline-ring"
					onMouseLeave={() => setHovered("")}
					onKeyDown={(event) => {
						if (!["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"].includes(event.key) || !countries.length) return
						event.preventDefault()
						setHovered("")
						const index = Math.max(
							0,
							countries.findIndex((row) => row.key === selected),
						)
						setSelected(
							countries[
								(index + (event.key === "ArrowLeft" || event.key === "ArrowUp" ? -1 : 1) + countries.length) %
									countries.length
							].key,
						)
					}}
				>
					<title>Event counts by country</title>
					{regions.map((region) => (
						<path
							key={region.code}
							data-country={region.code}
							d={region.path}
							fill={color(counts.get(region.code) || 0)}
							fillRule="evenodd"
							stroke={active === region.code ? "var(--foreground)" : "var(--card)"}
							strokeWidth={active === region.code ? 1.5 : 0.5}
							vectorEffect="non-scaling-stroke"
							className="cursor-pointer transition-colors"
							onMouseEnter={() => setHovered(region.code)}
							onClick={() => {
								setSelected(region.code)
								setHovered("")
							}}
						>
							<title>
								{name(region.code)}: {number(counts.get(region.code) || 0)} events
							</title>
						</path>
					))}
				</svg>
				<div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-1">
					<div aria-live="polite" className="rounded-lg border bg-muted/20 p-3">
						<p className="text-sm font-medium">{name(active)}</p>
						<p className="mt-1 text-2xl font-semibold text-emerald-600 dark:text-emerald-400">{number(count)}</p>
						<p className="text-xs text-muted-foreground">
							{total ? ((100 * count) / total).toFixed(1) : "0.0"}% of recorded events
						</p>
					</div>
					<div className="space-y-2 text-xs text-muted-foreground">
						<p>{countries.length} countries with events</p>
						<p>{number(unknown)} events with unknown or non-public IP countries</p>
						<p>Hover, tap, or choose a country to inspect its count.</p>
					</div>
				</div>
			</div>
			<div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground">
				<div className="flex items-center gap-2">
					<span>Fewer events</span>
					<span
						className="h-2 w-24 rounded-full"
						style={{ background: "linear-gradient(to right,hsl(160 65% 80%),hsl(160 65% 32%))" }}
					/>
					<span>More events</span>
				</div>
				<a href="https://www.naturalearthdata.com/" target="_blank" rel="noreferrer" className="underline">
					Map: Natural Earth
				</a>
			</div>
			<p className="mt-2 text-xs text-muted-foreground">
				Gray countries have no recorded events. Some small territories are only available in the country selector. IP
				location can identify a proxy or VPN.
			</p>
		</section>
	)
}
