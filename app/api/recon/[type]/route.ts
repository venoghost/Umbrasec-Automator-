import { type NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { authOptions } from "../../auth/[...nextauth]/route";
import { rateLimit } from "@/lib/rate-limit";

// CRITICAL SECURITY ISSUE: REMOVE HARDCODED API KEY
const SHODAN_API_KEY = "LwwAXud7NcvjV5Gagfe1Gg7RXoZotMo5";

if (!SHODAN_API_KEY) {
  throw new Error("SHODAN_API_KEY environment variable is not set");
}

// Configurable rate limit (adjust as needed)
const REQUESTS_PER_MINUTE = process.env.REQUESTS_PER_MINUTE
  ? parseInt(process.env.REQUESTS_PER_MINUTE, 10)
  : 50; // Default to 50 if not set

const limiter = rateLimit({
  interval: 60 * 1000, // 1 minute
  uniqueTokenPerInterval: 500,
});

async function resolveSubdomainToIP(subdomain: string, retries = 2): Promise<string | null> {
  for (let i = 0; i < retries; i++) {
    try {
      const response = await fetch(
        `https://api.shodan.io/dns/resolve?hostnames=${encodeURIComponent(subdomain)}&key=${SHODAN_API_KEY}`,
        { 
          signal: AbortSignal.timeout(5000),
          headers: {
            'Accept': 'application/json'
          }
        }
      );
      
      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Shodan DNS resolve failed: ${response.status} - ${errorText}`);
      }
      
      const data = await response.json();
      return data[subdomain] || null;
    } catch (error) {
      console.error(`Attempt ${i + 1} failed for ${subdomain}:`, error);
      if (i === retries - 1) return null;
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  }
  return null;
}

export async function POST(req: NextRequest, { params }: { params: { type: string } }) {
  const session = await getServerSession(authOptions);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  // Enhanced rate limiting with proper error handling
  try {
    await limiter.check(REQUESTS_PER_MINUTE, req.ip || 'unknown');
  } catch (error) {
    return NextResponse.json(
      { 
        error: "Rate limit exceeded", 
        message: `Limited to ${REQUESTS_PER_MINUTE} requests per minute. Please try again later.`,
        retryAfter: 60 // Seconds until reset
      }, 
      { status: 429 }
    );
  }

  const { type } = params;
  let body;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid request body" }, { status: 400 });
  }
  
  const { target } = body;

  // Enhanced input validation
  if (!target || typeof target !== "string") {
    return NextResponse.json({ error: "Valid target is required" }, { status: 400 });
  }

  // Input sanitization
  const sanitizedTarget = target.trim().toLowerCase();
  const domainRegex = /^[a-z0-9.-]+\.[a-z]{2,}$/;
  if (!domainRegex.test(sanitizedTarget)) {
    return NextResponse.json({ error: "Invalid domain format" }, { status: 400 });
  }

  try {
    let result;
    switch (type.toLowerCase()) {
      case "subdomains":
        const subdomainsResponse = await fetch(
          `https://api.shodan.io/dns/domain/${encodeURIComponent(sanitizedTarget)}?key=${SHODAN_API_KEY}`,
          { 
            signal: AbortSignal.timeout(10000),
            headers: {
              'Accept': 'application/json'
            }
          }
        );
        
        if (!subdomainsResponse.ok) {
          const errorText = await subdomainsResponse.text();
          throw new Error(`Shodan subdomains failed: ${subdomainsResponse.status} - ${errorText}`);
        }
        
        const subdomainData = await subdomainsResponse.json();
        
        if (subdomainData.subdomains?.length) {
          const subdomainIPs = await Promise.all(
            subdomainData.subdomains.map(async (subdomain: string) => {
              const fullDomain = `${subdomain}.${sanitizedTarget}`;
              const ip = await resolveSubdomainToIP(fullDomain);
              return { subdomain: fullDomain, ip };
            })
          );
          
          result = {
            domain: subdomainData.domain,
            subdomains: subdomainIPs.filter((entry) => entry.ip !== null),
            total: subdomainIPs.length,
          };
        } else {
          result = { domain: sanitizedTarget, subdomains: [], total: 0 };
        }
        break;

      default:
        return NextResponse.json({ error: "Invalid reconnaissance type" }, { status: 400 });
    }
    
    return NextResponse.json(result);
  } catch (error: any) {
    console.error(`Reconnaissance error for ${type}/${sanitizedTarget}:`, error);
    const status = error.message?.includes("Shodan") ? 400 : 500;
    return NextResponse.json(
      { error: error.message || "An error occurred during reconnaissance" },
      { status }
    );
  }
}

export const config = {
  runtime: "edge",
};