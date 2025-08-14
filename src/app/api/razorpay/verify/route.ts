import { NextResponse } from "next/server";
import crypto from "crypto";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";

export async function POST(req: Request) {
  try {
    const session = await auth();
    if (!session || !session.user || !session.user.id) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, plan } =
      await req.json();

    const text = razorpay_order_id + "|" + razorpay_payment_id;
    const generated_signature = crypto
      .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET!)
      .update(text)
      .digest("hex");

    if (generated_signature !== razorpay_signature) {
      console.error("Signature mismatch:", { generated_signature, razorpay_signature });
      return NextResponse.json({ error: "Invalid signature", details: { generated_signature, razorpay_signature } }, { status: 400 });
    }

    // Update user plan
    const updatedUser = await prisma.user.update({
      where: { id: session.user.id },
      data: { plan: plan as "BASIC" | "PRO" | "ENTERPRISE" },
    });

    return NextResponse.json({ success: true, plan: updatedUser.plan });
  } catch (error) {
    console.error("Error verifying payment:", error);
    return NextResponse.json(
      { error: "Failed to verify transaction", details: error instanceof Error ? error.message : String(error) },
      { status: 500 }
    );
  }
}
