"use client"

import { useState, useEffect } from "react"
import { getServerSession } from "next-auth/next"
import { redirect } from "next/navigation"
import { authOptions } from "../api/auth/[...nextauth]/route"
import { useRouter } from "next/navigation"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { useToast } from "@/components/ui/use-toast"

export default async function Settings() {
  const session = await getServerSession(authOptions)

  if (!session) {
    redirect("/login")
  }

  const router = useRouter()
  const { toast } = useToast()
  const [apiKeys, setApiKeys] = useState([])
  const [is2FAEnabled, setIs2FAEnabled] = useState(false)
  const [name, setName] = useState("")
  //const [email, setEmail] = useState("") //removed email

  useEffect(() => {
    //if (status === "unauthenticated") { //removed unauthenticated check
    //  router.push("/login")
    //} else
    if (session) {
      //added session check
      fetchApiKeys()
      check2FAStatus()
      setName(session.user.name || "")
      //setEmail(session.user.email || "") //removed email
    }
  }, [session]) //removed status and router from dependency array

  const fetchApiKeys = async () => {
    const res = await fetch("/api/user/api-keys")
    if (res.ok) {
      const data = await res.json()
      setApiKeys(data)
    }
  }

  const createApiKey = async () => {
    const res = await fetch("/api/user/api-keys", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "New API Key" }),
    })
    if (res.ok) {
      const data = await res.json()
      toast({
        title: "API Key Created",
        description: `Your new API key is: ${data.key}`,
      })
      fetchApiKeys()
    }
  }

  const deleteApiKey = async (id: string) => {
    const res = await fetch("/api/user/api-keys", {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id }),
    })
    if (res.ok) {
      toast({
        title: "API Key Deleted",
        description: "The API key has been successfully deleted.",
      })
      fetchApiKeys()
    }
  }

  const check2FAStatus = async () => {
    const res = await fetch("/api/auth/2fa")
    if (res.ok) {
      const data = await res.json()
      setIs2FAEnabled(data.enabled)
    }
  }

  const toggle2FA = async () => {
    if (is2FAEnabled) {
      // Disable 2FA
      const res = await fetch("/api/auth/2fa", { method: "DELETE" })
      if (res.ok) {
        setIs2FAEnabled(false)
        toast({
          title: "2FA Disabled",
          description: "Two-factor authentication has been disabled.",
        })
      }
    } else {
      // Enable 2FA
      router.push("/settings/enable-2fa")
    }
  }

  const updateProfile = async () => {
    try {
      const res = await fetch("/api/user/profile", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name }), //removed email
      })
      if (res.ok) {
        toast({
          title: "Profile Updated",
          description: "Your profile has been successfully updated.",
        })
      } else {
        throw new Error("Failed to update profile")
      }
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to update profile",
        variant: "destructive",
      })
    }
  }

  return (
    <div className="container mx-auto p-4">
      <h1 className="text-3xl font-bold mb-6">User Settings</h1>

      <Card className="mb-6">
        <CardHeader>
          <CardTitle>Profile Information</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div>
              <label htmlFor="name" className="block text-sm font-medium text-gray-700">
                Name
              </label>
              <Input id="name" value={name} onChange={(e) => setName(e.target.value)} />
            </div>
            {/*removed email input*/}
            <Button onClick={updateProfile}>Update Profile</Button>
          </div>
        </CardContent>
      </Card>

      <Card className="mb-6">
        <CardHeader>
          <CardTitle>Two-Factor Authentication</CardTitle>
        </CardHeader>
        <CardContent>
          <Button onClick={toggle2FA}>{is2FAEnabled ? "Disable 2FA" : "Enable 2FA"}</Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>API Keys</CardTitle>
        </CardHeader>
        <CardContent>
          <Button onClick={createApiKey} className="mb-4">
            Create New API Key
          </Button>
          {apiKeys.map((key: any) => (
            <div key={key.id} className="flex justify-between items-center mb-2">
              <span>{key.name}</span>
              <Button onClick={() => deleteApiKey(key.id)} variant="destructive">
                Delete
              </Button>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  )
}

