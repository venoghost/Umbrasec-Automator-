import { NextRequest, NextResponse } from "next/server";
import axios from "axios";
import { promises as dns } from "dns";
import portScanner from "portscanner";
import NodeCache from "node-cache";

// Types
interface ShodanData {
  ports?: number[];
  vulns?: string[];
  services?: { [port: number]: string };
  [key: string]: any;
}

interface CveDetails {
  description: string;
  cvss?: number;
  severity?: string;
  references?: string[];
  attacks: string[];
  googleSearchLink: string;
}

interface PortStatus {
  number: number;
  name: string;
  status: "open" | "closed";
  service?: string;
}

// Cache init
const cache = new NodeCache({ stdTTL: 3600, checkperiod: 600 });

// Mappings
const portNames: { [key: number]: string } = {
  21: "FTP Control",
  22: "SSH",
  23: "Telnet",
  25: "SMTP",
  53: "DNS",
  80: "HTTP",
  110: "POP3",
  143: "IMAP",
  443: "HTTPS",
  3306: "MySQL",
  8080: "HTTP-Alt",
  445: "SMB",
  3389: "RDP",
  5432: "PostgreSQL",
  6379: "Redis",
  27017: "MongoDB",
};

// Common ports to scan (removed port 20)
const commonPorts = [
  21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 3306, 5432, 6379, 8080, 27017,
];

// Web vulnerabilities mapping (non-CVE vulnerabilities)
const webVulnToAttacks: { [key: string]: string[] } = {
  "Missing X-Content-Type-Options": ["MIME-Type Sniffing"],
  "Missing X-Frame-Options": ["Clickjacking"],
  "Missing Content-Security-Policy": ["XSS"],
  "Missing Strict-Transport-Security": ["MITM"],
  "Server Header Exposed": ["Information Disclosure"],
  "Directory Listing Enabled": ["Information Disclosure"],
};

// Web scanner
const scanWebsiteVulnerabilities = async (
  url: string,
  openPorts: PortStatus[]
): Promise<string | { [key: string]: { description: string; attacks: string[] } }> => {
  const results: { [key: string]: { description: string; attacks: string[] } } = {};
  try {
    const hasWebPort = openPorts.some((p) => [80, 443, 8080].includes(p.number));
    if (!hasWebPort) return "No web ports detected";

    const res = await axios.get(`https://${url}`, { timeout: 5000, validateStatus: () => true });
    const headers = res.headers;

    if (!headers["x-content-type-options"])
      results["Missing X-Content-Type-Options"] = {
        description: "Should be set to 'nosniff' to prevent MIME-type sniffing.",
        attacks: webVulnToAttacks["Missing X-Content-Type-Options"],
      };
    if (!headers["x-frame-options"])
      results["Missing X-Frame-Options"] = {
        description: "Should be set to 'DENY' or 'SAMEORIGIN'.",
        attacks: webVulnToAttacks["Missing X-Frame-Options"],
      };
    if (!headers["content-security-policy"])
      results["Missing Content-Security-Policy"] = {
        description: "Should define allowed sources to mitigate XSS.",
        attacks: webVulnToAttacks["Missing Content-Security-Policy"],
      };
    if (!headers["strict-transport-security"])
      results["Missing Strict-Transport-Security"] = {
        description: "Should enforce HTTPS (e.g., max-age).",
        attacks: webVulnToAttacks["Missing Strict-Transport-Security"],
      };
    if (headers["server"])
      results["Server Header Exposed"] = {
        description: `Exposed: ${headers["server"]}`,
        attacks: webVulnToAttacks["Server Header Exposed"],
      };

    const dirCheck = await axios.get(`https://${url}/nonexistent_dir/`, {
      timeout: 5000,
      validateStatus: () => true,
    });

    if (dirCheck.data.includes("Index of"))
      results["Directory Listing Enabled"] = {
        description: "Directory listing is enabled.",
        attacks: webVulnToAttacks["Directory Listing Enabled"],
      };

    return Object.keys(results).length > 0 ? results : "No web vulnerabilities detected";
  } catch {
    return {
      "Scan Error": { description: "Error occurred during web scan", attacks: ["N/A"] },
    };
  }
};

// Port scanner
const scanPorts = async (ip: string): Promise<PortStatus[]> => {
  const portResults: PortStatus[] = [];

  await Promise.all(
    commonPorts.map(async (port) => {
      try {
        const status = await portScanner.checkPortStatus(port, ip);
        let service = portNames[port] || "Unknown";

        if (status === "open") {
          try {
            const bannerRes = await axios.get(`http://${ip}:${port}`, { timeout: 2000 });
            const banner = bannerRes.headers["server"] || "No banner";
            service += ` (${banner})`;
          } catch {}
          // Append FTP Data to service for port 21 if open
          if (port === 21) {
            service += ", FTP Data";
          }
        }

        portResults.push({
          number: port,
          name: portNames[port] || "Unknown",
          status: status as "open" | "closed",
          service: status === "open" ? service : undefined,
        });
      } catch {
        portResults.push({
          number: port,
          name: portNames[port] || "Unknown",
          status: "closed",
        });
      }
    })
  );

  return portResults.sort((a, b) => a.number - b.number);
};

// Heuristic function to derive attacks based on CVE description or severity
const deriveAttacksFromCve = (cve: string, description: string, cvss?: number): string[] => {
  // Placeholder: Derive attacks based on description keywords or CVSS score
  const descLower = description.toLowerCase();
  const attacks: string[] = [];

  // Example heuristic based on description keywords
  if (descLower.includes("arbitrary code") || descLower.includes("remote code execution")) {
    attacks.push("Remote Code Execution");
  }
  if (descLower.includes("privilege escalation") || descLower.includes("elevation of privilege")) {
    attacks.push("Privilege Escalation");
  }
  if (descLower.includes("sql injection")) {
    attacks.push("SQL Injection");
  }
  if (descLower.includes("cross-site scripting") || descLower.includes("xss")) {
    attacks.push("XSS");
  }
  if (descLower.includes("denial of service") || descLower.includes("dos")) {
    attacks.push("Denial of Service");
  }
  if (descLower.includes("information disclosure") || descLower.includes("leak")) {
    attacks.push("Information Disclosure");
  }

  // Example heuristic based on CVSS score
  if (cvss !== undefined) {
    if (cvss >= 9) {
      attacks.push("Critical Exploitation");
    } else if (cvss >= 7) {
      attacks.push("High Severity Attack");
    }
  }

  // Fallback for specific known CVEs (placeholder until a proper database is integrated)
  if (cve === "CVE-2017-15906") {
    attacks.push("Arbitrary File Write", "Privilege Escalation");
  }

  return attacks.length > 0 ? attacks : ["N/A"];
};

// CVE info with fallback
const fetchCveDetails = async (cve: string, retries = 2): Promise<CveDetails> => {
  const cacheKey = `cve:${cve}`;
  const cached = cache.get(cacheKey);
  if (cached) return cached as CveDetails;

  let desc = "";
  let cvss: number | undefined = undefined;
  let severity: string | undefined = undefined;
  let references: string[] = [];
  let attacks: string[] = [];
  const googleSearchLink = `https://www.google.com/search?q=${cve}`;
  const vulnersKey = process.env.VULNERS_API_KEY;

  // Helper function to set severity based on CVSS
  const setSeverity = (score: number): string => {
    return score >= 9 ? "Critical" : score >= 7 ? "High" : score >= 4 ? "Medium" : "Low";
  };

  try {
    const res = await axios.get(`https://vulners.com/api/v3/search/id/?id=${cve}`, {
      headers: { "X-Vulners-API-Key": vulnersKey ?? "" },
      timeout: 5000,
    });
    const data = res.data?.data?.search?.[0]?._source;
    if (data) {
      desc = data.description || desc;
      cvss = data.cvss?.score;
      if (cvss !== undefined) {
        severity = setSeverity(cvss);
      }
      references = data.references || [];
    }
  } catch {}

  if (desc === "") {
    try {
      const res = await axios.get(`https://cveawg.mitre.org/api/cve/${cve}`, { timeout: 5000 });
      desc = res.data?.cve?.description?.description_data?.[0]?.value || desc;
      const cvssData = res.data?.cve?.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore;
      if (cvssData !== undefined) {
        cvss = cvssData;
        severity = setSeverity(cvssData);
      }
    } catch {}
  }

  if (desc === "") {
    try {
      const res = await axios.get(`https://cve.circl.lu/api/cve/${cve}`, { timeout: 5000 });
      desc = res.data?.summary || desc;
      const cvssData = res.data?.cvss;
      if (cvssData !== undefined) {
        cvss = cvssData;
        severity = setSeverity(cvssData);
      }
      references = res.data?.references || references;
    } catch {}
  }

  // Derive attacks dynamically based on CVE description and CVSS
  if (desc) {
    attacks = deriveAttacksFromCve(cve, desc, cvss);
  } else {
    desc = "No description available";
    attacks = ["N/A"];
  }

  const result: CveDetails = { description: desc, cvss, severity, references, attacks, googleSearchLink };
  cache.set(cacheKey, result);
  return result;
};

export async function POST(req: NextRequest) {
  try {
    const { input } = await req.json();

    if (!input || typeof input !== "string") {
      return NextResponse.json({ error: "Provide valid IP or domain" }, { status: 400 });
    }

    let ip: string;
    let resolvedDomain: string | null = null;
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;

    if (ipRegex.test(input)) {
      ip = input;
    } else {
      try {
        const resolved = await dns.resolve4(input);
        ip = resolved[0];
        resolvedDomain = input;
      } catch {
        return NextResponse.json({ error: "Invalid domain or resolution failed" }, { status: 400 });
      }
    }

    let shodanData: ShodanData = {};
    try {
      const res = await axios.get(`https://internetdb.shodan.io/${ip}`, {
        signal: AbortSignal.timeout(10000),
      });
      shodanData = res.data;
    } catch {
      shodanData = {};
    }

    // Scan ports automatically
    const portResults = await scanPorts(ip);

    // Prepare openPorts for web vulnerability scanning
    const openPorts: PortStatus[] = portResults.filter((p) => p.status === "open");

    // Merge Shodan ports with scanned ports
    const shodanPorts = Array.isArray(shodanData.ports) ? shodanData.ports : [];
    shodanPorts.forEach((port: number) => {
      if (!portResults.some((p) => p.number === port)) {
        portResults.push({
          number: port,
          name: portNames[port] || "Unknown",
          status: "open",
          service: shodanData.services?.[port] || "Shodan",
        });
      }
    });

    let ipData = {};
    try {
      const ipRes = await axios.get(`http://ip-api.com/json/${ip}`, { timeout: 5000 });
      ipData = ipRes.data;
    } catch {
      ipData = { error: "GeoIP failed" };
    }

    const vulnerabilities: Record<string, CveDetails> = {};
    const shodanVulns = Array.isArray(shodanData.vulns) ? shodanData.vulns : [];
    await Promise.all(
      shodanVulns.map(async (vuln: string) => {
        const details = await fetchCveDetails(vuln);
        if (details) {
          vulnerabilities[vuln] = details;
        }
      })
    );

    const webVulns = resolvedDomain
      ? await scanWebsiteVulnerabilities(resolvedDomain, openPorts)
      : "N/A";

    return NextResponse.json({
      ip,
      domain: resolvedDomain,
      ports: portResults.length ? portResults : "No ports scanned",
      vulns: Object.keys(vulnerabilities).length ? vulnerabilities : "No vulnerabilities found",
      webVulns,
      data: ipData,
      shodanData,
    });
  } catch (err) {
    console.error("Scan error:", err);
    return NextResponse.json({ error: "Scan failed" }, { status: 500 });
  }
}