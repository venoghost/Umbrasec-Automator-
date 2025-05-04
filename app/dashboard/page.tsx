
"use client";
import { useState, useRef, useEffect } from "react";
import axios from "axios";
import html2canvas from "html2canvas";
import jsPDF from "jspdf";
import { FaFilePdf, FaFileCsv, FaChevronDown, FaChevronUp, FaSpinner } from "react-icons/fa";

// Mapping of ports to possible attacks
const portToAttacks: { [key: number]: string[] } = {
  21: ["Brute Force", "FTP Bounce Attack"],
  22: ["Brute Force", "SSH Tunneling"],
  23: ["Brute Force", "Packet Sniffing"],
  25: ["Email Spoofing", "SMTP Relay"],
  53: ["DNS Spoofing", "Cache Poisoning"],
  80: ["XSS", "SQL Injection", "HTTP Header Injection"],
  110: ["Credential Harvesting", "Data Interception"],
  143: ["Credential Harvesting", "Data Interception"],
  443: ["SSL Stripping", "XSS", "SQL Injection"],
  445: ["SMB Relay", "Ransomware"],
  3389: ["Brute Force", "RDP Hijacking"],
  3306: ["SQL Injection", "Database Enumeration"],
  5432: ["SQL Injection", "Database Enumeration"],
  6379: ["Unauthorized Access", "Data Exfiltration"],
  8080: ["XSS", "SQL Injection", "HTTP Header Injection"],
  27017: ["Unauthorized Access", "Data Exfiltration"],
};

export default function Dashboard() {
  const [input, setInput] = useState("");
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [expandedCves, setExpandedCves] = useState<{ [key: string]: boolean }>({});
  const reportRef = useRef<HTMLDivElement>(null);

  // Simulate scan progress during loading
  useEffect(() => {
    if (loading) {
      const interval = setInterval(() => {
        setProgress((prev) => (prev >= 90 ? 90 : prev + 10));
      }, 500);
      return () => clearInterval(interval);
    } else {
      setProgress(0);
    }
  }, [loading]);

  // Handle scan form submission
  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setResult(null);
    setLoading(true);
    setExpandedCves({});

    try {
      const response = await axios.post("/api/scan", { input });
      setResult(response.data);
      setProgress(100);
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

  // Toggle CVE details visibility
  const toggleCve = (cve: string) => {
    setExpandedCves((prev) => ({ ...prev, [cve]: !prev[cve] }));
  };

  // Export report to PDF
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

  // Export report to CSV
  const exportToCSV = () => {
    if (!result) return;
    const rows = [
      ["Section", "Key", "Value"],
      ["IP", "", result.ip || "N/A"],
      ["Domain", "", result.domain || "N/A"],
      ...Array.isArray(result.ports)
        ? result.ports
            .filter((p: any) => p.number !== 20) // Exclude port 20
            .map((p: any) => {
              const service =
                p.number === 21 && p.status === "open"
                  ? p.service
                    ? `${p.service}, FTP Data`
                    : "FTP Control, FTP Data"
                  : p.service || "N/A";
              return [
                "Ports",
                `${p.number}/${p.name}`,
                `Status: ${p.status}, Service: ${service}${
                  p.status === "open" && portToAttacks[p.number]
                    ? `, Possible Attacks: ${portToAttacks[p.number].join(", ")}`
                    : ""
                }`,
              ];
            })
        : [["Ports", "", result.ports || "None"]],
      ...Object.entries(result.vulns || {}).flatMap(([cve, details]: [string, any]) => [
        ["Vulnerabilities", cve, `CVSS: ${details.cvss || "N/A"}`],
        ["Vulnerabilities", cve, `Severity: ${details.severity || "N/A"}`],
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

  // Calculate scan summary metrics
  const openPortsCount = Array.isArray(result?.ports)
    ? result.ports.filter((p: any) => p.status === "open" && p.number !== 20).length
    : 0;
  const cveCount = result?.vulns && typeof result.vulns === "object" ? Object.keys(result.vulns).length : 0;
  const webVulnCount = result?.webVulns && typeof result.webVulns === "object" ? Object.keys(result.webVulns).length : 0;

  return (
    <div className="min-h-screen bg-gray-900 text-gray-100 flex flex-col items-center justify-center px-4 py-12 font-mono relative overflow-hidden">
      {/* Background Grid Pattern */}
      <div className="absolute inset-0 bg-grid-pattern opacity-10 pointer-events-none" />

      <h1 className="text-6xl font-extrabold mb-12 text-center tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-pink-500 animate-glow">
        UmbrasecAutomater
      </h1>

      <form onSubmit={handleScan} className="flex flex-col sm:flex-row gap-4 w-full max-w-3xl bg-gray-800/80 backdrop-blur-md rounded-2xl p-6 border border-cyan-500/50 shadow-lg shadow-cyan-500/20 transition-all duration-500 hover:shadow-cyan-500/40">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Enter IP or Domain (e.g., 192.168.1.1)"
          className="flex-1 px-5 py-3 rounded-xl bg-gray-700/50 border border-gray-600 text-gray-100 focus:outline-none focus:ring-2 focus:ring-cyan-500 transition duration-300 placeholder-gray-400"
        />
        <button
          type="submit"
          disabled={loading}
          className={`px-6 py-3 rounded-xl font-semibold transition duration-300 flex items-center justify-center gap-2 ${
            loading
              ? "bg-gray-600 cursor-not-allowed text-gray-400"
              : "bg-gradient-to-r from-cyan-500 to-pink-500 hover:from-cyan-600 hover:to-pink-600 text-white shadow-lg shadow-cyan-500/30"
          }`}
        >
          {loading ? (
            <>
              <FaSpinner className="animate-spin" /> Scanning...
            </>
          ) : (
            "Initiate Scan"
          )}
        </button>
      </form>

      {error && (
        <p className="mt-6 text-red-400 font-semibold bg-red-900/50 backdrop-blur-md p-4 rounded-xl border border-red-500/50 animate-fade-in">{error}</p>
      )}

      {loading && (
        <div className="mt-10 w-full max-w-4xl space-y-6">
          <div className="bg-gray-800/80 backdrop-blur-md p-6 rounded-2xl border border-cyan-500/50">
            <h3 className="text-xl font-semibold text-cyan-400 mb-4">Scan Progress</h3>
            <div className="w-full bg-gray-700 rounded-full h-4 overflow-hidden">
              <div
                className="bg-gradient-to-r from-cyan-500 to-pink-500 h-full transition-all duration-500"
                style={{ width: `${progress}%` }}
              />
            </div>
            <p className="text-sm text-gray-400 mt-2">Analyzing {input}... {progress}%</p>
          </div>
          <div className="space-y-4 animate-pulse">
            {Array.from({ length: 3 }).map((_, i) => (
              <div key={i} className="h-12 bg-gray-700/50 rounded-2xl w-full" />
            ))}
          </div>
        </div>
      )}

      {result && (
        <div
          ref={reportRef}
          id="scan-report"
          className="mt-10 w-full max-w-4xl space-y-8 animate-fade-in"
        >
          {/* Scan Summary Widget */}
          <div className="bg-gray-800/80 backdrop-blur-md p-6 rounded-2xl border border-cyan-500/50 shadow-lg shadow-cyan-500/20">
            <h2 className="text-2xl font-bold text-gray-100 mb-4">Scan Summary</h2>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="bg-gray-700/50 p-4 rounded-xl border border-cyan-500/30">
                <p className="text-sm text-gray-400">Open Ports</p>
                <p className="text-2xl font-bold text-cyan-400">{openPortsCount}</p>
              </div>
              <div className="bg-gray-700/50 p-4 rounded-xl border border-pink-500/30">
                <p className="text-sm text-gray-400">CVE Vulnerabilities</p>
                <p className="text-2xl font-bold text-pink-400">{cveCount}</p>
              </div>
              <div className="bg-gray-700/50 p-4 rounded-xl border border-purple-500/30">
                <p className="text-sm text-gray-400">Web Vulnerabilities</p>
                <p className="text-2xl font-bold text-purple-400">{webVulnCount}</p>
              </div>
            </div>
          </div>

          <div className="flex flex-col sm:flex-row justify-between items-center gap-4 bg-gray-800/80 backdrop-blur-md p-6 rounded-2xl border border-cyan-500/50 shadow-lg shadow-cyan-500/20">
            <h2 className="text-3xl font-bold text-gray-100">
              Scan Report for <span className="text-cyan-400">{input}</span>
              {result.ip && input !== result.ip ? (
                <span className="text-gray-400"> (IP: {result.ip})</span>
              ) : null}
            </h2>
            <div className="flex gap-3">
              <button
                onClick={exportToPDF}
                className="bg-gradient-to-r from-red-500 to-red-700 hover:from-red-600 hover:to-red-800 text-white px-4 py-2 rounded-xl text-sm flex items-center gap-2 shadow-lg shadow-red-500/30 transition duration-300"
              >
                <FaFilePdf /> PDF
              </button>
              <button
                onClick={exportToCSV}
                className="bg-gradient-to-r from-green-500 to-green-700 hover:from-green-600 hover:to-green-800 text-white px-4 py-2 rounded-xl text-sm flex items-center gap-2 shadow-lg shadow-green-500/30 transition duration-300"
              >
                <FaFileCsv /> CSV
              </button>
            </div>
          </div>

          <Section title="Ports">
            {Array.isArray(result.ports) ? (
              <div className="overflow-x-auto rounded-2xl shadow-inner border border-cyan-500/50">
                <table className="w-full text-sm text-left bg-gray-800/80 backdrop-blur-md rounded-2xl">
                  <thead className="text-xs uppercase bg-gray-700/50 text-gray-300">
                    <tr>
                      <th className="px-6 py-4">Port</th>
                      <th className="px-6 py-4">Service</th>
                      <th className="px-6 py-4">Status</th>
                      <th className="px-6 py-4">Possible Attacks</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.ports
                      .filter((p: any) => p.number !== 20) // Exclude port 20
                      .map((p: any) => {
                        const service =
                          p.number === 21 && p.status === "open"
                            ? p.service
                              ? `${p.service}, FTP Data`
                              : "FTP Control, FTP Data"
                            : p.service || "N/A";
                        return (
                          <tr
                            key={p.number}
                            className="border-b border-gray-700 hover:bg-gray-700/50 transition duration-200"
                          >
                            <td className="px-6 py-4 font-medium text-cyan-400">{p.number}/{p.name}</td>
                            <td className="px-6 py-4 text-gray-300">{service}</td>
                            <td className="px-6 py-4">
                              <span
                                className={`px-3 py-1 rounded-full text-xs font-semibold ${
                                  p.status === "open"
                                    ? "bg-green-900/50 text-green-400 border border-green-500/50"
                                    : "bg-red-900/50 text-red-400 border border-red-500/50"
                                }`}
                              >
                                {p.status}
                              </span>
                            </td>
                            <td className="px-6 py-4 text-gray-300">
                              {p.status === "open" && portToAttacks[p.number]
                                ? portToAttacks[p.number].join(", ")
                                : "N/A"}
                            </td>
                          </tr>
                        );
                      })}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="text-sm text-gray-400">{result.ports}</p>
            )}
          </Section>

          <Section title="CVE Vulnerabilities">
            {result.vulns && typeof result.vulns === "object" && Object.keys(result.vulns).length > 0 ? (
              <ul className="space-y-4">
                {Object.entries(result.vulns).map(([cve, details]: [string, any]) => (
                  <li key={cve} className="border-b border-gray-700 pb-4">
                    <div
                      className="flex justify-between items-center cursor-pointer hover:bg-gray-700/50 p-4 rounded-xl transition duration-200"
                      onClick={() => toggleCve(cve)}
                    >
                      <div>
                        <strong className="text-cyan-400 font-semibold">{cve}</strong>
                        {details.severity && (
                          <span
                            className={`ml-3 px-3 py-1 rounded-full text-xs font-semibold border ${
                              details.severity === "Critical"
                                ? "bg-red-900/50 text-red-400 border-red-500/50"
                                : details.severity === "High"
                                ? "bg-orange-900/50 text-orange-400 border-orange-500/50"
                                : details.severity === "Medium"
                                ? "bg-yellow-900/50 text-yellow-400 border-yellow-500/50"
                                : "bg-green-900/50 text-green-400 border-green-500/50"
                            }`}
                          >
                            {details.severity}
                          </span>
                        )}
                      </div>
                      {expandedCves[cve] ? <FaChevronUp className="text-gray-500" /> : <FaChevronDown className="text-gray-500" />}
                    </div>
                    {expandedCves[cve] && (
                      <div className="mt-3 text-sm space-y-3 p-4 bg-gray-700/50 rounded-xl border border-cyan-500/30">
                        {details.cvss && <p><strong className="text-gray-400">CVSS Score:</strong> <span className="text-gray-300">{details.cvss}</span></p>}
                        {details.references?.length > 0 && (
                          <p>
                            <strong className="text-gray-400">References:</strong>{" "}
                            {details.references.map((ref: string, i: number) => (
                              <a
                                key={i}
                                href={ref}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-cyan-400 hover:underline mr-2"
                              >
                                [{i + 1}]
                              </a>
                            ))}
                          </p>
                        )}
                        <p>
                          <strong className="text-gray-400">More Info:</strong>{" "}
                          <a
                            href={details.googleSearchLink}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-cyan-400 hover:underline"
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
              <p className="text-sm text-gray-400">{typeof result.vulns === "string" ? result.vulns : "No CVE vulnerabilities found."}</p>
            )}
          </Section>

          <Section title="Web Vulnerabilities">
            {typeof result.webVulns === "object" && Object.keys(result.webVulns).length > 0 ? (
              <ul className="list-disc pl-6 space-y-3 text-sm">
                {Object.entries(result.webVulns).map(([key, details]: [string, any]) => (
                  <li key={key} className="p-4 bg-gray-700/50 rounded-xl hover:bg-gray-600/50 transition duration-200 border border-purple-500/30">
                    <strong className="text-purple-400">{key}</strong>: <span className="text-gray-300">{details.description}</span>
                    <br />
                    <em className="text-gray-400">Possible Attacks:</em>{" "}
                    <span className="text-gray-300">{details.attacks?.join(", ") || "N/A"}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-gray-400">{result.webVulns || "No web vulnerabilities found."}</p>
            )}
          </Section>

          {result.shodanData?.hostnames?.length > 0 && (
            <Section title="Hostnames">
              <p className="text-sm text-gray-300">{result.shodanData.hostnames.join(", ")}</p>
            </Section>
          )}

          {result.shodanData?.cpes?.length > 0 && (
            <Section title="CPEs">
              <ul className="list-disc pl-6 space-y-2 text-sm">
                {result.shodanData.cpes.map((cpe: string, index: number) => (
                  <li key={index} className="text-gray-300">{cpe}</li>
                ))}
              </ul>
            </Section>
          )}

          <Section title="IP Data">
            <pre className="bg-gray-800 p-4 rounded-xl border border-cyan-500/50 text-sm text-cyan-400 terminal-style overflow-x-auto">
              {JSON.stringify(result.data, null, 2)}
            </pre>
          </Section>

          <Section title="InternetDB Data">
            <pre className="bg-gray-800 p-4 rounded-xl border border-cyan-500/50 text-sm text-cyan-400 terminal-style overflow-x-auto">
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
    <div className="bg-gray-800/80 backdrop-blur-md p-6 rounded-2xl border border-cyan-500/50 shadow-lg shadow-cyan-500/20 transition-all duration-500 hover:shadow-cyan-500/40">
      <h3 className="text-xl font-semibold text-cyan-400 mb-4 border-b border-gray-700 pb-2">{title}:</h3>
      <div className="text-sm">{children}</div>
    </div>
  );
}
