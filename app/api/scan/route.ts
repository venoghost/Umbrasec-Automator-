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

// Cache init
const cache = new NodeCache({ stdTTL: 3600, checkperiod: 600 });

// Mappings
const portNames: { [key: number]: string } = {
  20: "FTP Data", 21: "FTP Control", 22: "SSH", 23: "Telnet", 25: "SMTP",
  53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
  3306: "MySQL", 8080: "HTTP-Alt",
};

const vulnToAttacks: { [key: string]: string[] } = {
  "CVE-2017-15906": ["Arbitrary File Write", "Privilege Escalation"],
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
  openPorts: { number: number; name: string; service?: string }[]
): Promise<string | { [key: string]: { description: string; attacks: string[] } }> => {
  const results: { [key: string]: { description: string; attacks: string[] } } = {};
  try {
    const hasWebPort = openPorts.some(p => [80, 443, 8080].includes(p.number));
    if (!hasWebPort) return "No web ports detected";

    const res = await axios.get(`https://${url}`, { timeout: 5000, validateStatus: () => true });
    const headers = res.headers;

    if (!headers["x-content-type-options"])
      results["Missing X-Content-Type-Options"] = {
        description: "Should be set to 'nosniff' to prevent MIME-type sniffing.",
        attacks: vulnToAttacks["Missing X-Content-Type-Options"],
      };
    if (!headers["x-frame-options"])
      results["Missing X-Frame-Options"] = {
        description: "Should be set to 'DENY' or 'SAMEORIGIN'.",
        attacks: vulnToAttacks["Missing X-Frame-Options"],
      };
    if (!headers["content-security-policy"])
      results["Missing Content-Security-Policy"] = {
        description: "Should define allowed sources to mitigate XSS.",
        attacks: vulnToAttacks["Missing Content-Security-Policy"],
      };
    if (!headers["strict-transport-security"])
      results["Missing Strict-Transport-Security"] = {
        description: "Should enforce HTTPS (e.g., max-age).",
        attacks: vulnToAttacks["Missing Strict-Transport-Security"],
      };
    if (headers["server"])
      results["Server Header Exposed"] = {
        description: `Exposed: ${headers["server"]}`,
        attacks: vulnToAttacks["Server Header Exposed"],
      };

    const dirCheck = await axios.get(`https://${url}/nonexistent_dir/`, {
      timeout: 5000, validateStatus: () => true,
    });

    if (dirCheck.data.includes("Index of"))
      results["Directory Listing Enabled"] = {
        description: "Directory listing is enabled.",
        attacks: vulnToAttacks["Directory Listing Enabled"],
      };

    return Object.keys(results).length > 0 ? results : "No web vulnerabilities detected";
  } catch {
    return {
      "Scan Error": { description: "Error occurred during web scan", attacks: ["N/A"] }
    };
  }
};

// CVE info with fallback
const fetchCveDetails = async (cve: string, retries = 2): Promise<CveDetails> => {
  const cacheKey = `cve:${cve}`;
  const cached = cache.get(cacheKey);
  if (cached) return cached as CveDetails;

  let desc = "Unknown vulnerability";
  let cvss: number | undefined = undefined;
  let severity: string | undefined = undefined;
  let references: string[] = [];
  const attacks = vulnToAttacks[cve] || ["Unknown"];
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

  if (desc === "Unknown vulnerability") {
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

  if (desc === "Unknown vulnerability") {
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

    const openPorts: { number: number; name: string; service?: string }[] = [];
    const shodanPorts = Array.isArray(shodanData.ports) ? shodanData.ports : [];
    shodanPorts.forEach((port: number) => {
      if (!openPorts.some(p => p.number === port))
        openPorts.push({
          number: port,
          name: portNames[port] || "Unknown",
          service: shodanData.services?.[port] || "Shodan",
        });
    });

    const portsToScan = [22, 80, 443, 3306, 8080];
    await Promise.all(portsToScan.map(async port => {
      try {
        const status = await portScanner.checkPortStatus(port, ip);
        if (status === "open" && !openPorts.some(p => p.number === port)) {
          let service = portNames[port] || "Unknown";
          try {
            const bannerRes = await axios.get(`http://${ip}:${port}`, { timeout: 2000 });
            const banner = bannerRes.headers["server"] || "No banner";
            service += ` (${banner})`;
          } catch {}
          openPorts.push({ number: port, name: portNames[port], service });
        }
      } catch {}
    }));

    let ipData = {};
    try {
      const ipRes = await axios.get(`http://ip-api.com/json/${ip}`, { timeout: 5000 });
      ipData = ipRes.data;
    } catch {
      ipData = { error: "GeoIP failed" };
    }

    const vulnerabilities: Record<string, CveDetails> = {};
    const shodanVulns = Array.isArray(shodanData.vulns) ? shodanData.vulns : [];
    await Promise.all(shodanVulns.map(async (vuln: string) => {
      const details = await fetchCveDetails(vuln);
      vulnerabilities[vuln] = details;
    }));

    const webVulns = resolvedDomain
      ? await scanWebsiteVulnerabilities(resolvedDomain, openPorts)
      : "N/A";

    return NextResponse.json({
      ip,
      domain: resolvedDomain,
      ports: openPorts.length ? openPorts : "No open ports found",
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