"use client";
import { useState, useRef } from "react";
import axios from "axios";
import html2canvas from "html2canvas";
import jsPDF from "jspdf";
import { FaFilePdf, FaFileCsv, FaChevronDown, FaChevronUp } from "react-icons/fa";

export default function Home() {
  const [input, setInput] = useState("");
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [expandedCves, setExpandedCves] = useState<{ [key: string]: boolean }>({});
  const reportRef = useRef<HTMLDivElement>(null);

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setResult(null);
    setLoading(true);
    setExpandedCves({});

    try {
      const response = await axios.post("/api/scan", { input });
      setResult(response.data);
    } catch (err: unknown) {
      if (axios.isAxiosError(err)) {
        setError(err.response?.data?.error || "Failed to perform scan");
      } else {
        setError("An unexpected error occurred");
      }
    } finally {
      setLoading(false);
    }
  };

  const toggleCve = (cve: string) => {
    setExpandedCves((prev) => ({ ...prev, [cve]: !prev[cve] }));
  };

  const exportToPDF = () => {
    if (reportRef.current) {
      html2canvas(reportRef.current, { scale: 2 }).then((canvas) => {
        const pdf = new jsPDF("p", "mm", "a4");
        const imgData = canvas.toDataURL("image/png");
        const imgProps = pdf.getImageProperties(imgData);
        const pdfWidth = pdf.internal.pageSize.getWidth();
        const pdfHeight = (imgProps.height * pdfWidth) / imgProps.width;
        pdf.addImage(imgData, "PNG", 0, 0, pdfWidth, pdfHeight);
        pdf.save("scan-report.pdf");
      });
    }
  };

  const exportToCSV = () => {
    if (!result) return;
    const rows = [
      ["Section", "Key", "Value"],
      ["IP", "", result.ip || "N/A"],
      ["Domain", "", result.domain || "N/A"],
      ["Ports", "", Array.isArray(result.ports)
        ? result.ports.map((p: any) => `${p.number}/${p.name}${p.service ? ` (${p.service})` : ""}`).join("; ")
        : result.ports || "None"],
      ...Object.entries(result.vulns || {}).flatMap(([cve, details]: [string, any]) => [
        ["Vulnerabilities", cve, `Description: ${details.description}`],
        ["Vulnerabilities", cve, `CVSS: ${details.cvss || "N/A"}`],
        ["Vulnerabilities", cve, `Severity: ${details.severity || "N/A"}`],
        ["Vulnerabilities", cve, `Attacks: ${details.attacks?.join(", ") || "N/A"}`],
        ["Vulnerabilities", cve, `References: ${details.references?.join(", ") || "N/A"}`],
      ]),
      ...Object.entries(result.webVulns || {}).map(([key, details]: [string, any]) => [
        "Web Vulnerabilities",
        key,
        `Description: ${details.description}, Attacks: ${details.attacks?.join(", ") || "N/A"}`,
      ]),
      ["Hostnames", "", result.shodanData?.hostnames?.join(", ") || "None"],
      ...result.shodanData?.cpes?.map((cpe: string) => ["CPEs", "", cpe]) || [],
      ["IP Data", "", JSON.stringify(result.data, null, 2)],
      ["Shodan Data", "", JSON.stringify(result.shodanData, null, 2)],
    ];
    const csvContent =
      "data:text/csv;charset=utf-8," +
      rows.map((e) => e.map((v: any) => `"${v}"`).join(",")).join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", "scan-report.csv");
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="min-h-screen bg-white dark:bg-gray-900 text-gray-900 dark:text-gray-100 transition-colors duration-300 flex flex-col items-center justify-center px-4 py-8 font-sans">
      <h1 className="text-4xl font-extrabold mb-8 text-center tracking-tight">
        Scan IP Addresses with <span className="text-blue-600 dark:text-blue-400">Umbrasec</span>
      </h1>

      <form onSubmit={handleScan} className="flex flex-col sm:flex-row gap-4 w-full max-w-2xl">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Enter IP or Domain (e.g., example.com)"
          className="flex-1 px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 focus:outline-none focus:ring-2 focus:ring-blue-500 transition"
        />
        <button
          type="submit"
          disabled={loading}
          className={`px-5 py-2 rounded-lg font-semibold transition ${
            loading ? "bg-gray-400 cursor-not-allowed text-white" : "bg-blue-600 hover:bg-blue-700 text-white"
          }`}
        >
          {loading ? "Scanning..." : "Scan"}
        </button>
      </form>

      {error && (
        <p className="mt-4 text-red-500 font-medium bg-red-100 dark:bg-red-900/30 p-3 rounded-lg">{error}</p>
      )}

      {loading && (
        <div className="mt-8 w-full max-w-4xl space-y-4 animate-pulse">
          <div className="h-8 bg-gray-300 dark:bg-gray-700 rounded w-1/2" />
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="h-6 bg-gray-300 dark:bg-gray-700 rounded w-full" />
          ))}
        </div>
      )}

      {result && (
        <div
          ref={reportRef}
          id="scan-report"
          className="mt-8 w-full max-w-4xl bg-gray-50 dark:bg-gray-800 p-6 rounded-xl shadow-lg space-y-6"
        >
          <div className="flex justify-between items-center">
            <h2 className="text-2xl font-bold">
              Scan Report for {input}
              {result.ip && input !== result.ip ? ` (Resolved IP: ${result.ip})` : ""}
            </h2>
            <div className="flex gap-2">
              <button
                onClick={exportToPDF}
                className="bg-red-600 hover:bg-red-700 text-white px-3 py-1 rounded text-sm flex items-center gap-1"
              >
                <FaFilePdf /> PDF
              </button>
              <button
                onClick={exportToCSV}
                className="bg-green-600 hover:bg-green-700 text-white px-3 py-1 rounded text-sm flex items-center gap-1"
              >
                <FaFileCsv /> CSV
              </button>
            </div>
          </div>

          <Section title="Ports">
            <p className="text-sm">
              {Array.isArray(result.ports)
                ? result.ports.map((p: any) => (
                    <span key={p.number} className="inline-block mr-2">
                      {p.number}/{p.name}
                      {p.service ? ` (${p.service})` : ""}
                    </span>
                  ))
                : result.ports}
            </p>
          </Section>

          <Section title="CVE Vulnerabilities">
            {result.vulns && Object.keys(result.vulns).length > 0 ? (
              <ul className="space-y-4">
                {Object.entries(result.vulns).map(([cve, details]: [string, any]) => (
                  <li key={cve} className="border-b border-gray-200 dark:border-gray-700 pb-2">
                    <div
                      className="flex justify-between items-center cursor-pointer"
                      onClick={() => toggleCve(cve)}
                    >
                      <div>
                        <strong className="text-blue-600 dark:text-blue-400">{cve}</strong>
                        {details.severity && (
                          <span
                            className={`ml-2 px-2 py-1 rounded text-xs ${
                              details.severity === "Critical"
                                ? "bg-red-600 text-white"
                                : details.severity === "High"
                                ? "bg-orange-500 text-white"
                                : details.severity === "Medium"
                                ? "bg-yellow-500 text-black"
                                : "bg-green-500 text-white"
                            }`}
                          >
                            {details.severity}
                          </span>
                        )}
                      </div>
                      {expandedCves[cve] ? <FaChevronUp /> : <FaChevronDown />}
                    </div>
                    {expandedCves[cve] && (
                      <div className="mt-2 text-sm space-y-2">
                        <p><strong>Description:</strong> {details.description}</p>
                        {details.cvss && <p><strong>CVSS Score:</strong> {details.cvss}</p>}
                        <p><strong>Possible Attacks:</strong> {details.attacks?.join(", ") || "N/A"}</p>
                        {details.references?.length > 0 && (
                          <p>
                            <strong>References:</strong>{" "}
                            {details.references.map((ref: string, i: number) => (
                              <a
                                key={i}
                                href={ref}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-blue-500 hover:underline"
                              >
                                [{i + 1}]
                              </a>
                            ))}
                          </p>
                        )}
                        <p>
                          <strong>More Info:</strong>{" "}
                          <a
                            href={details.googleSearchLink}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-blue-500 hover:underline"
                          >
                            Google Search
                          </a>
                        </p>
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            ) : (
              <p>No CVE vulnerabilities found.</p>
            )}
          </Section>

          <Section title="Web Vulnerabilities">
            {typeof result.webVulns === "object" && Object.keys(result.webVulns).length > 0 ? (
              <ul className="list-disc pl-5 space-y-2 text-sm">
                {Object.entries(result.webVulns).map(([key, details]: [string, any]) => (
                  <li key={key}>
                    <strong>{key}</strong>: {details.description}
                    <br />
                    <em>Possible Attacks:</em> {details.attacks?.join(", ") || "N/A"}
                  </li>
                ))}
              </ul>
            ) : (
              <p>{result.webVulns || "No web vulnerabilities found."}</p>
            )}
          </Section>

          {result.shodanData?.hostnames?.length > 0 && (
            <Section title="Hostnames">
              <p className="text-sm">{result.shodanData.hostnames.join(", ")}</p>
            </Section>
          )}

          {result.shodanData?.cpes?.length > 0 && (
            <Section title="CPEs">
              <ul className="list-disc pl-5 space-y-1 text-sm">
                {result.shodanData.cpes.map((cpe: string, index: number) => (
                  <li key={index}>{cpe}</li>
                ))}
              </ul>
            </Section>
          )}

          <Section title="IP Data">
            <pre className="bg-gray-100 dark:bg-gray-700 p-4 rounded-md overflow-x-auto text-sm">
              {JSON.stringify(result.data, null, 2)}
            </pre>
          </Section>

          <Section title="InternetDB Data">
            <pre className="bg-gray-100 dark:bg-gray-700 p-4 rounded-md overflow-x-auto text-sm">
              {JSON.stringify(result.shodanData, null, 2)}
            </pre>
          </Section>
        </div>
      )}
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="text-lg font-semibold text-gray-700 dark:text-gray-200 mb-2">{title}:</h3>
      <div className="text-sm">{children}</div>
    </div>
  );
}
