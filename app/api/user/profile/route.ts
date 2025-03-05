import { type NextRequest, NextResponse } from "next/server"
import { getServerSession } from "next-auth/next"
import { authOptions } from "../../auth/[...nextauth]/route"
import { PrismaClient } from "@prisma/client"

const prisma = new PrismaClient()

export async function PUT(req: NextRequest) {
  const session = await getServerSession(authOptions)
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }

  const userId = session.user.id
  const { name } = await req.json()

  try {
    const updatedUser = await prisma.user.update({
      where: { id: userId },
      data: { name },
    })
    return NextResponse.json({ success: true, user: updatedUser })
  } catch (error) {
    console.error(error)
    return NextResponse.json({ error: "Failed to update profile" }, { status: 500 })
  }
}

