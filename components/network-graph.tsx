"use client"

import { useEffect, useRef } from "react"
import { ForceGraph2D } from "react-force-graph"

export function NetworkGraph({ data }: { data: any }) {
  const graphRef = useRef<any>()

  useEffect(() => {
    if (graphRef.current) {
      graphRef.current.d3Force("charge").strength(-120)
    }
  }, [])

  const graphData = {
    nodes: [
      { id: "target", group: 1 },
      ...(data.subdomains?.map((subdomain: string) => ({ id: subdomain, group: 2 })) || []),
      ...(data.ports?.map((port: number) => ({ id: `port-${port}`, group: 3 })) || []),
    ],
    links: [
      ...(data.subdomains?.map((subdomain: string) => ({ source: "target", target: subdomain })) || []),
      ...(data.ports?.map((port: number) => ({ source: "target", target: `port-${port}` })) || []),
    ],
  }

  return (
    <ForceGraph2D
      ref={graphRef}
      graphData={graphData}
      nodeAutoColorBy="group"
      nodeLabel={(node: any) => node.id}
      linkDirectionalParticles={2}
      linkDirectionalParticleSpeed={0.005}
    />
  )
}

