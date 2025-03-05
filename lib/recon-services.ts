import { Resolver } from "dns/promises"
import whois from "whois-json"
//@ts-ignore
import { createClient } from "shodan-client"

if (!process.env.SHODAN_API_KEY) {
  throw new Error("SHODAN_API_KEY environment variable is not set")
}

const shodanClient = createClient("LwwAXud7NcvjV5Gagfe1Gg7RXoZotMo5")
const resolver = new Resolver()

export async function findSubdomains(domain: string): Promise<string[]> {
  if (!domain) {
    throw new Error("Domain parameter is required")
  }

  try {
    const searchResults = await shodanClient.search(`hostname:${domain}`)
    return Array.from(new Set(searchResults.matches.flatMap((match: any) => match.hostnames || [])))
  } catch (error) {
    console.error("Error in findSubdomains:", error)
    throw new Error("Failed to find subdomains")
  }
}

export async function scanPorts(target: string): Promise<number[]> {
  if (!target) {
    throw new Error("Target parameter is required")
  }

  try {
    const hostInfo = await shodanClient.host(target)
    return hostInfo.ports || []
  } catch (error) {
    console.error("Error in scanPorts:", error)
    throw new Error("Failed to scan ports")
  }
}

export async function identifyServices(target: string): Promise<{ [key: number]: string }> {
  if (!target) {
    throw new Error("Target parameter is required")
  }

  try {
    const hostInfo = await shodanClient.host(target)
    return hostInfo.data.reduce((acc: { [key: number]: string }, service: any) => {
      acc[service.port] = service.product || service._shodan.module
      return acc
    }, {})
  } catch (error) {
    console.error("Error in identifyServices:", error)
    throw new Error("Failed to identify services")
  }
}

export async function whoisLookup(domain: string): Promise<any> {
  if (!domain) {
    throw new Error("Domain parameter is required")
  }

  try {
    return await whois(domain)
  } catch (error) {
    console.error("Error in whoisLookup:", error)
    throw new Error("Failed to perform WHOIS lookup")
  }
}

export async function dnsEnumeration(domain: string): Promise<any[]> {
  if (!domain) {
    throw new Error("Domain parameter is required")
  }

  const recordTypes = ["A", "AAAA", "MX", "NS", "TXT", "SOA"]
  try {
    const results = await Promise.all(
      recordTypes.map(async (type) => {
        try {
          const records = await resolver.resolve(domain, type as any)
          return { type, records }
        } catch (error) {
          return { type, records: [] }
        }
      }),
    )
    return results.filter((result) => result.records.length > 0)
  } catch (error) {
    console.error("Error in dnsEnumeration:", error)
    throw new Error("Failed to perform DNS enumeration")
  }
}

export async function scanVulnerabilities(target: string): Promise<any[]> {
  if (!target) {
    throw new Error("Target parameter is required")
  }

  try {
    const hostInfo = await shodanClient.host(target)
    if (!hostInfo.vulns) {
      return []
    }
    return hostInfo.vulns.map((vuln: string) => ({
      id: vuln,
      details: hostInfo.data.find((service: any) => service.vulns && service.vulns.includes(vuln)),
    }))
  } catch (error) {
    console.error("Error in scanVulnerabilities:", error)
    throw new Error("Failed to scan vulnerabilities")
  }
}
