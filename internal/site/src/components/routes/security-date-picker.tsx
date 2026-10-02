import { useState, useRef, useEffect } from "react"
import { CalendarDays, ChevronDown, ChevronLeft, ChevronRight } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"

export type SecurityDateRange = { from: string; to: string; preset: "all" | "30d" | "7d" | "today" | "custom" }
export function dateKey(date: Date) {
	return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`
}
export function presetRange(preset: Exclude<SecurityDateRange["preset"], "custom">): SecurityDateRange {
	const end = new Date(),
		start = new Date(end)
	if (preset === "7d") start.setDate(start.getDate() - 6)
	if (preset === "30d") start.setDate(start.getDate() - 29)
	return { from: dateKey(start), to: dateKey(end), preset }
}
export function rangeParams(range: SecurityDateRange) {
	if (range.preset === "all") return { range: "all" }
	const end = new Date(`${range.to}T00:00:00`)
	end.setDate(end.getDate() + 1)
	return { from: String(new Date(`${range.from}T00:00:00`).getTime() / 1000), to: String(end.getTime() / 1000) }
}
const presets = [
	{ key: "all", label: "All time" },
	{ key: "30d", label: "30 days" },
	{ key: "7d", label: "7 days" },
	{ key: "today", label: "Today" },
] as const
const prettyDate = (value: string) =>
	new Date(`${value}T00:00:00`).toLocaleDateString("en", { month: "short", day: "numeric", year: "numeric" })

export function SecurityDatePicker({
	value,
	onChange,
}: {
	value: SecurityDateRange
	onChange: (range: SecurityDateRange) => void
}) {
	const [open, setOpen] = useState(false)
	const [draft, setDraft] = useState({ from: value.from, to: value.to })
	const [month, setMonth] = useState(() => new Date(`${value.from}T00:00:00`))
	const [focusDate, setFocusDate] = useState(value.from)
	const calendar = useRef<HTMLDivElement>(null)
	const today = dateKey(new Date())
	const label =
		presets.find((item) => item.key === value.preset)?.label || `${prettyDate(value.from)} to ${prettyDate(value.to)}`
	const monthStart = new Date(month.getFullYear(), month.getMonth(), 1)
	const start = new Date(monthStart)
	start.setDate(1 - ((monthStart.getDay() + 6) % 7))
	const days = Array.from({ length: 42 }, (_, index) => {
		const date = new Date(start)
		date.setDate(date.getDate() + index)
		return date
	})
	useEffect(() => {
		if (open)
			calendar.current?.querySelector<HTMLButtonElement>(`[data-date="${focusDate}"]`)?.focus({ preventScroll: true })
	}, [focusDate])
	function choose(date: string) {
		setFocusDate(date)
		if (!draft.from || draft.to) setDraft({ from: date, to: "" })
		else setDraft(date < draft.from ? { from: date, to: draft.from } : { from: draft.from, to: date })
	}
	return (
		<Dialog
			open={open}
			onOpenChange={(next) => {
				setOpen(next)
				if (next) {
					setDraft({ from: value.from, to: value.to })
					setMonth(new Date(`${value.from}T00:00:00`))
					setFocusDate(value.from)
				}
			}}
		>
			<DialogTrigger asChild>
				<Button variant="outline" aria-label="Date range" className="h-9 max-w-full justify-between gap-2 px-3">
					<CalendarDays className="size-4 shrink-0 text-muted-foreground" />
					<span className="truncate text-sm">{label}</span>
					<ChevronDown className="size-4 shrink-0 text-muted-foreground" />
				</Button>
			</DialogTrigger>
			<DialogContent className="w-[calc(100%-2rem)] max-w-sm gap-3 rounded-lg p-4">
				<DialogTitle>Date range</DialogTitle>
				<DialogDescription>Choose a preset or select a start and end date.</DialogDescription>
				<div className="grid grid-cols-4 gap-1 border-b pb-3">
					{presets.map((item) => (
						<Button
							key={item.key}
							variant={value.preset === item.key ? "secondary" : "ghost"}
							size="sm"
							className="px-1 text-xs"
							onClick={() => {
								onChange(presetRange(item.key))
								setOpen(false)
							}}
						>
							{item.label}
						</Button>
					))}
				</div>
				<div className="flex items-center justify-between gap-2">
					<Button
						variant="ghost"
						size="icon"
						className="size-8"
						aria-label="Previous month"
						disabled={month.getFullYear() === 1970 && month.getMonth() === 0}
						onClick={() => setMonth(new Date(month.getFullYear(), month.getMonth() - 1, 1))}
					>
						<ChevronLeft className="size-4" />
					</Button>
					<div className="flex gap-1">
						<Select
							value={String(month.getMonth())}
							onValueChange={(value) => setMonth(new Date(month.getFullYear(), Number(value), 1))}
						>
							<SelectTrigger aria-label="Calendar month" className="h-8 w-auto gap-2 border-0 px-2">
								<SelectValue />
							</SelectTrigger>
							<SelectContent>
								{Array.from({ length: 12 }, (_, index) => (
									<SelectItem key={index} value={String(index)}>
										{new Date(2000, index, 1).toLocaleDateString("en", { month: "long" })}
									</SelectItem>
								))}
							</SelectContent>
						</Select>
						<Select
							value={String(month.getFullYear())}
							onValueChange={(value) => setMonth(new Date(Number(value), month.getMonth(), 1))}
						>
							<SelectTrigger aria-label="Calendar year" className="h-8 w-auto gap-2 border-0 px-2">
								<SelectValue />
							</SelectTrigger>
							<SelectContent>
								{Array.from(
									{ length: new Date().getFullYear() - 1969 },
									(_, index) => new Date().getFullYear() - index,
								).map((year) => (
									<SelectItem key={year} value={String(year)}>
										{year}
									</SelectItem>
								))}
							</SelectContent>
						</Select>
					</div>
					<Button
						variant="ghost"
						size="icon"
						className="size-8"
						aria-label="Next month"
						disabled={monthStart >= new Date(new Date().getFullYear(), new Date().getMonth(), 1)}
						onClick={() => setMonth(new Date(month.getFullYear(), month.getMonth() + 1, 1))}
					>
						<ChevronRight className="size-4" />
					</Button>
				</div>
				<div ref={calendar} role="group" aria-label="Select dates" className="grid grid-cols-7 gap-1">
					{["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"].map((day) => (
						<span key={day} className="py-1 text-center text-xs text-muted-foreground">
							{day}
						</span>
					))}
					{days.map((date) => {
						const key = dateKey(date),
							edge = key === draft.from || key === draft.to,
							inside = !!draft.to && key > draft.from && key < draft.to
						return (
							<button
								type="button"
								key={key}
								data-date={key}
								aria-label={date.toLocaleDateString("en", {
									weekday: "long",
									month: "long",
									day: "numeric",
									year: "numeric",
								})}
								aria-pressed={edge || inside}
								tabIndex={
									key === (days.some((day) => dateKey(day) === focusDate) ? focusDate : dateKey(monthStart)) ? 0 : -1
								}
								disabled={key > today || key < "1970-01-01"}
								className={`h-9 rounded-md text-sm focus-visible:outline-2 focus-visible:outline-ring disabled:opacity-30 ${edge ? "bg-primary text-primary-foreground" : inside ? "bg-muted text-foreground" : "hover:bg-accent"} ${date.getMonth() !== month.getMonth() && !edge ? "text-muted-foreground" : ""}`}
								onClick={() => choose(key)}
								onKeyDown={(event) => {
									const offset: Record<string, number> = { ArrowLeft: -1, ArrowRight: 1, ArrowUp: -7, ArrowDown: 7 }
									if (!offset[event.key]) return
									event.preventDefault()
									const next = new Date(date)
									next.setDate(next.getDate() + offset[event.key])
									const nextKey = dateKey(next)
									if (nextKey > today || nextKey < "1970-01-01") return
									setMonth(new Date(next.getFullYear(), next.getMonth(), 1))
									setFocusDate(nextKey)
								}}
							>
								{date.getDate()}
							</button>
						)
					})}
				</div>
				<div className="border-t pt-3">
					<p className="mb-3 text-xs text-muted-foreground" aria-live="polite">
						{draft.to
							? `${prettyDate(draft.from)} to ${prettyDate(draft.to)}.`
							: `Start: ${prettyDate(draft.from)}. Select an end date.`}{" "}
						Dates use your local time zone.
					</p>
					<div className="flex justify-end gap-2">
						<Button variant="outline" size="sm" onClick={() => setOpen(false)}>
							Cancel
						</Button>
						<Button
							size="sm"
							disabled={!draft.from || !draft.to}
							onClick={() => {
								onChange({ ...draft, preset: "custom" })
								setOpen(false)
							}}
						>
							Apply dates
						</Button>
					</div>
				</div>
			</DialogContent>
		</Dialog>
	)
}
