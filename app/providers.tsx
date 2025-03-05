"use client"

import type React from "react"

import { ThemeProvider } from "next-themes"
import { SessionProvider } from "next-auth/react"

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <ThemeProvider attribute="class" defaultTheme="dark" enableSystem={false}>
      <SessionProvider>{children}</SessionProvider>
    </ThemeProvider>
  )
}

