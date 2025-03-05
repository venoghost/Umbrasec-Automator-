"use client"

import { signIn } from "next-auth/react"
import { useRouter } from "next/navigation"
import { Button } from "@/components/ui/button"

export default function Login() {
  const router = useRouter()

  const handleGoogleSignIn = () => {
    signIn("google", { callbackUrl: "/dashboard" })
  }

  return (
    <div className="flex flex-col items-center justify-center min-h-screen p-4 bg-gray-900">
      <h1 className="text-3xl font-bold mb-6 text-white">Login to Umbrasec Automator</h1>
      <Button onClick={handleGoogleSignIn} className="w-full max-w-md">
        Sign Up with Google
      </Button>
    </div>
  )
}

