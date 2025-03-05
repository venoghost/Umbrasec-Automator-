"use client"

import { useState, useEffect } from "react"
import { useSession } from "next-auth/react" // Changed to useSession hook
import { redirect } from "next/navigation"
import { useRouter } from "next/navigation"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useToast } from "@/components/ui/use-toast"
import { Slider } from "@/components/ui/slider"
import { NetworkGraph } from "@/components/network-graph"
import { ReportGenerator } from "@/components/report-generator"
import { CollaborationPanel } from "@/components/collaboration-panel"
import { ThreatIntelligence } from "@/components/threat-intelligence"

export default function Dashboard() {
  const router = useRouter()
  const { data: session, status } = useSession() // Use next-auth useSession hook
  const [target, setTarget] = useState("")
  const [results, setResults] = useState<any>({})
  const [scanOptions, setScanOptions] = useState({
    portRange: [1, 1000],
    timeout: 5000,
    concurrency: 10,
  })
  const { toast } = useToast()

  useEffect(() => {
    // Redirect if not authenticated
    if (status === "unauthenticated") {
      router.push('/login')
    }
  }, [status, router])

  // Don't render content until authentication is checked
  if (status === "loading") {
    return <div>Loading...</div>
  }

  if (!session) {
    return null // Will redirect in useEffect
  }

  const handleRecon = async (type: string) => {
    try {
      const response = await fetch(`/api/recon/${type}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, options: scanOptions }),
      })

      if (!response.ok) {
        throw new Error("Reconnaissance failed")
      }

      const data = await response.json()
      setResults({ ...results, [type]: data })
    } catch (error) {
      toast({
        title: "Error",
        description: "An error occurred during reconnaissance",
        variant: "destructive",
      })
    }
  }

  return (
    <div className="container mx-auto p-4">
      <h1 className="text-3xl font-bold mb-6">NetSentry Dashboard</h1>
      <Card className="mb-6">
        <CardContent className="pt-6">
          <Input
            placeholder="Enter target domain or IP"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            className="mb-4"
          />
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block mb-2">Port Range</label>
              <Slider
                min={1}
                max={65535}
                step={1}
                value={scanOptions.portRange}
                onValueChange={(value) => setScanOptions({ ...scanOptions, portRange: value })}
              />
            </div>
            <div>
              <label className="block mb-2">Timeout (ms)</label>
              <Input
                type="number"
                value={scanOptions.timeout}
                onChange={(e) => setScanOptions({ ...scanOptions, timeout: Number.parseInt(e.target.value) })}
              />
            </div>
            <div>
              <label className="block mb-2">Concurrency</label>
              <Input
                type="number"
                value={scanOptions.concurrency}
                onChange={(e) => setScanOptions({ ...scanOptions, concurrency: Number.parseInt(e.target.value) })}
              />
            </div>
          </div>
        </CardContent>
      </Card>
      <Tabs defaultValue="subdomains" className="space-y-4">
        <TabsList>
          <TabsTrigger value="subdomains">Subdomains</TabsTrigger>
          <TabsTrigger value="ports">Ports</TabsTrigger>
          <TabsTrigger value="services">Services</TabsTrigger>
          <TabsTrigger value="whois">WHOIS</TabsTrigger>
          <TabsTrigger value="dns">DNS</TabsTrigger>
          <TabsTrigger value="vulnerabilities">Vulnerabilities</TabsTrigger>
          <TabsTrigger value="visualization">Visualization</TabsTrigger>
          <TabsTrigger value="threatIntel">Threat Intel</TabsTrigger>
        </TabsList>
        <TabsContent value="subdomains">
          <ReconCard
            title="Subdomain Discovery"
            onScan={() => handleRecon("subdomains")}
            results={results.subdomains}
          />
        </TabsContent>
        <TabsContent value="ports">
          <ReconCard title="Port Scanning" onScan={() => handleRecon("ports")} results={results.ports} />
        </TabsContent>
        <TabsContent value="services">
          <ReconCard title="Service Identification" onScan={() => handleRecon("services")} results={results.services} />
        </TabsContent>
        <TabsContent value="whois">
          <ReconCard title="WHOIS Lookup" onScan={() => handleRecon("whois")} results={results.whois} />
        </TabsContent>
        <TabsContent value="dns">
          <ReconCard title="DNS Enumeration" onScan={() => handleRecon("dns")} results={results.dns} />
        </TabsContent>
        <TabsContent value="vulnerabilities">
          <ReconCard
            title="Vulnerability Scan"
            onScan={() => handleRecon("vulnerabilities")}
            results={results.vulnerabilities}
          />
        </TabsContent>
        <TabsContent value="visualization">
          <Card>
            <CardHeader>
              <CardTitle>Network Visualization</CardTitle>
            </CardHeader>
            <CardContent>
              <NetworkGraph data={results} />
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="threatIntel">
          <Card>
            <CardHeader>
              <CardTitle>Threat Intelligence</CardTitle>
            </CardHeader>
            <CardContent>
              <ThreatIntelligence target={target} />
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
      <div className="mt-8 grid grid-cols-1 md:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle>Report Generation</CardTitle>
          </CardHeader>
          <CardContent>
            <ReportGenerator results={results} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Collaboration</CardTitle>
          </CardHeader>
          <CardContent>
            <CollaborationPanel />
          </CardContent>
        </Card>
      </div>
    </div>
  )
}

function ReconCard({ title, onScan, results }: { title: string; onScan: () => void; results: any }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardContent>
        <Button onClick={onScan}>Scan</Button>
        {results && (
          <div className="mt-4">
            {Array.isArray(results) ? (
              <ul className="list-disc pl-5">
                {results.map((item: any, index: number) => (
                  <li key={index}>
                    {typeof item === "object"
                      ? Object.entries(item)
                          .map(([key, value]) => `${key}: ${value}`)
                          .join(", ")
                      : item}
                  </li>
                ))}
              </ul>
            ) : typeof results === "object" ? (
              <ul className="list-disc pl-5">
                {Object.entries(results).map(([key, value]) => (
                  <li key={key}>{`${key}: ${value}`}</li>
                ))}
              </ul>
            ) : (
              <p>{results}</p>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
