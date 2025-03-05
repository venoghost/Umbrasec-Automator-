import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"

export function ReportGenerator({ results }: { results: any }) {
  const [selectedSections, setSelectedSections] = useState<string[]>([])

  const handleGenerateReport = () => {
    // Logic to generate report based on selectedSections and results
    console.log("Generating report with sections:", selectedSections)
  }

  return (
    <div>
      <div className="space-y-2">
        {Object.keys(results).map((section) => (
          <div key={section} className="flex items-center space-x-2">
            <Checkbox
              id={section}
              checked={selectedSections.includes(section)}
              onCheckedChange={(checked) => {
                setSelectedSections(
                  checked ? [...selectedSections, section] : selectedSections.filter((s) => s !== section),
                )
              }}
            />
            <label htmlFor={section}>{section}</label>
          </div>
        ))}
      </div>
      <Button onClick={handleGenerateReport} className="mt-4">
        Generate Report
      </Button>
    </div>
  )
}

