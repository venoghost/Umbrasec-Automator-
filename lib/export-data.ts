import { saveAs } from "file-saver"

export function exportToCSV(data: any[], filename: string) {
  const csvContent = data.map((row) => Object.values(row).join(",")).join("\n")
  const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8" })
  saveAs(blob, `${filename}.csv`)
}

export function exportToPDF(data: any[], filename: string) {
  // This is a placeholder. In a real application, you'd use a library like jsPDF to generate the PDF
  console.log("Exporting to PDF:", data)
  alert("PDF export not implemented yet")
}

