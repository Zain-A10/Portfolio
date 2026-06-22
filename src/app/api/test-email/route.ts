import { NextResponse } from "next/server";
import { resend } from "../../lib/email";

export async function GET() {
  try {
    const response = await resend.emails.send({
      from: process.env.STORE_EMAIL!,
      to: process.env.ADMIN_EMAIL!,
      subject: "Test Email",
      html: "<h2>This is a test email from your app</h2>",
    });

    console.log("Email response:", response);

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error("Email test failed:", error);
    return NextResponse.json({ error: "Email failed" }, { status: 500 });
  }
}