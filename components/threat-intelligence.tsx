"use client"

import { useEffect, useState } from "react"
import { Card, CardContent } from "@/components/ui/card"

export function ThreatIntelligence({ target }: { target: string }) {
  const [threatData, setThreatData] = useState<any>(null)

  useEffect(() => {
    const fetchThreatIntel = async () => {
      // This would be an API call to a threat intelligence service
      // For demonstration, we're using mock data
      const mockThreatData = {
        riskScore: 75,
        recentMaliciousActivities: [
          { date: "2023-06-01", type: "Phishing Campaign" },
          { date: "2023-05-15", type: "Malware Distribution" },
        ],
        associatedThreatActors: ["APT29", "Lazarus Group"],
      }
      setThreatData(mockThreatData)
    }

    if (target) {
      fetchThreatIntel()
    }
  }, [target])

  if (!threatData) {
    return <div>Loading threat intelligence...</div>
  }

  return (
    <Card>
      <CardContent>
        <h3 className="text-lg font-semibold mb-2">Threat Intelligence for {target}</h3>
        <p>Risk Score: {threatData.riskScore}</p>
        <h4 className="font-semibold mt-4 mb-2">Recent Malicious Activities:</h4>
        <ul>
          {threatData.recentMaliciousActivities.map((activity: any, index: number) => (
            <li key={index}>
              {activity.date}: {activity.type}
            </li>
          ))}
        </ul>
        <h4 className="font-semibold mt-4 mb-2">Associated Threat Actors:</h4>
        <ul>
          {threatData.associatedThreatActors.map((actor: string, index: number) => (
            <li key={index}>{actor}</li>
          ))}
        </ul>
      </CardContent>
    </Card>
  )
}

