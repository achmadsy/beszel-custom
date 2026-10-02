import { useState } from "react"
import { Check, ChevronDown } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from "@/components/ui/command"

const names = new Intl.DisplayNames(["en"], { type: "region" })
const countryName = (code: string) =>
	/^[A-Z]{2}$/.test(code) ? names.of(code) || code : code === "LOCAL" ? "Non-public IP" : "Unknown"

export function SecurityCountryFilter({
	value,
	onChange,
	countries,
}: {
	value: string
	onChange: (value: string) => void
	countries: { key: string; count: number }[]
}) {
	const [open, setOpen] = useState(false)
	const [search, setSearch] = useState("")
	const options = [
		{ value: "", label: "All countries" },
		...countries
			.filter((row) => /^[A-Z]{2}$/.test(row.key))
			.map((row) => ({ value: row.key, label: countryName(row.key) }))
			.sort((a, b) => a.label.localeCompare(b.label)),
		{ value: "UNKNOWN", label: "Unknown" },
		{ value: "LOCAL", label: "Non-public IP" },
	]
	return (
		<Dialog
			open={open}
			onOpenChange={(next) => {
				setOpen(next)
				if (next) setSearch("")
			}}
		>
			<DialogTrigger asChild>
				<Button
					variant="outline"
					role="combobox"
					aria-label="Country filter"
					aria-expanded={open}
					className="h-9 max-w-full justify-between gap-3 px-3"
				>
					<span className="truncate">{value ? countryName(value) : "All countries"}</span>
					<ChevronDown className="size-4 shrink-0 text-muted-foreground" />
				</Button>
			</DialogTrigger>
			<DialogContent className="w-[calc(100%-2rem)] max-w-sm gap-0 overflow-hidden rounded-lg p-0">
				<DialogTitle className="sr-only">Filter by country</DialogTitle>
				<DialogDescription className="sr-only">
					Search for a country name or two-letter country code, then select it.
				</DialogDescription>
				<Command label="Search countries">
					<CommandInput
						aria-label="Search countries"
						placeholder="Search country or code"
						value={search}
						onValueChange={setSearch}
						className="pr-10"
					/>
					<CommandList className="max-h-[min(60dvh,320px)]">
						<CommandEmpty>No matching countries</CommandEmpty>
						<CommandGroup>
							{options.map((option) => (
								<CommandItem
									key={option.value || "all"}
									value={`${option.label} ${option.value}`}
									onSelect={() => {
										onChange(option.value)
										setOpen(false)
									}}
								>
									<Check className={`size-4 ${value === option.value ? "opacity-100" : "opacity-0"}`} />
									<span>{option.label}</span>
									{/^[A-Z]{2}$/.test(option.value) && (
										<span className="ml-auto text-xs text-muted-foreground">{option.value}</span>
									)}
								</CommandItem>
							))}
						</CommandGroup>
					</CommandList>
				</Command>
			</DialogContent>
		</Dialog>
	)
}
