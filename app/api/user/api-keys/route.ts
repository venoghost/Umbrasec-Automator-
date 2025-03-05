import { type NextRequest, NextResponse } from "next/server"
import { getServerSession } from "next-auth/next"
import { authOptions } from "../../auth/[...nextauth]/route"
import { PrismaClient } from "@prisma/client"
import crypto from "crypto"

const prisma = new PrismaClient()

export async function GET(req: NextRequest) {
  const session = await getServerSession(authOptions)
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }

  const userId = session.user.id

  try {
    const apiKeys = await prisma.apiKey.findMany({
      where: { userId },
      select: { id: true, name: true, createdAt: true, lastUsed: true },
    })
    return NextResponse.json(apiKeys)
  } catch (error) {
    console.error(error)
    return NextResponse.json({ error: "Failed to fetch API keys" }, { status: 500 })
  }
}

export async function POST(req: NextRequest) {
  const session = await getServerSession(authOptions)
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }

  const userId = session.user.id
  const { name } = await req.json()

  try {
    const key = crypto.randomBytes(32).toString("hex")
    const apiKey = await prisma.apiKey.create({
      data: { key, name, userId },
    })
    return NextResponse.json({ id: apiKey.id, key })
  } catch (error) {
    console.error(error)
    return NextResponse.json({ error: "Failed to create API key" }, { status: 500 })
  }
}

export async function DELETE(req: NextRequest) {
  const session = await getServerSession(authOptions)
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }

  const userId = session.user.id
  const { id } = await req.json()

  try {
    await prisma.apiKey.deleteMany({
      where: { id, userId },
    })
    return NextResponse.json({ success: true })
  } catch (error) {
    console.error(error)
    return NextResponse.json({ error: "Failed to delete API key" }, { status: 500 })
  }
}

