import { NextApiRequest, NextApiResponse } from "next";
import { promises as dns } from "dns";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  
  const { target } = req.body;

  if (!target || typeof target !== "string") {
    return res.status(400).json({ error: "Domain is required" });
  }

  try {
    // Resolve domain to IP using Node.js dns module
    const ipList = await dns.resolve4(target);
    if (!ipList || ipList.length === 0) {
      return res.status(404).json({ error: "No IP found for this domain" });
    }
    const ip = ipList[0]; // Use the first IP

    // Query Shodan InternetDB
    const shodanResponse = await fetch(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`, {
      signal: AbortSignal.timeout(10000), // 10s timeout
    });

    if (!shodanResponse.ok) {
      const errorText = await shodanResponse.text();
      return res.status(shodanResponse.status).json({
        error: `Shodan lookup failed: ${shodanResponse.status} - ${errorText || "No details"}`,
      });
    }

    const shodanData = await shodanResponse.json();
    const result = { ip, ...shodanData };

    return res.status(200).json(result);
  } catch (error) {
    console.error("Scan error:", error);
    const errorMsg = error instanceof Error ? error.message : "Internal server error";
    return res.status(500).json({ error: errorMsg });
  }
}