import Link from "next/link"
import { Button } from "@/components/ui/button"

export default function Home() {
  return (
    <div className="flex flex-col items-center justify-center min-h-screen p-4 bg-gradient-to-b from-gray-900 to-black text-white">
      <h1 className="text-5xl font-bold mb-6">Welcome to NetSentry</h1>
      <p className="text-xl mb-8 text-center max-w-2xl">
        Discover vulnerabilities, scan networks, and secure your digital assets with our advanced cybersecurity tool.
      </p>
      <div className="space-x-4">
        <Button asChild>
          <Link href="/login">Login</Link>
        </Button>
        <Button asChild variant="outline">
          <Link href="/signup">Sign Up</Link>
        </Button>
      </div>
      <div className="mt-12 grid grid-cols-1 md:grid-cols-3 gap-8">
        <FeatureCard title="Network Scanning" description="Comprehensive port scanning and service identification." />
        <FeatureCard
          title="Vulnerability Assessment"
          description="Identify and analyze potential security weaknesses."
        />
        <FeatureCard title="Threat Intelligence" description="Stay informed with the latest cybersecurity insights." />
      </div>
    </div>
  )
}

function FeatureCard({ title, description }: { title: string; description: string }) {
  return (
    <div className="bg-gray-800 p-6 rounded-lg">
      <h3 className="text-xl font-semibold mb-2">{title}</h3>
      <p>{description}</p>
    </div>
  )
}

