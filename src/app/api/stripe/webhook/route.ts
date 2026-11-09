
import { NextResponse } from "next/server";
import Stripe from "stripe";
import { stripe } from "../../../lib/stripe";
import { supabaseAdmin } from "../../../lib/supabaseAdmin";
import { resend } from "../../../lib/email";

export const runtime = "nodejs";

type CartItem = {
  id: number;
  name: string;
  price: number;
  quantity: number;
};

export async function POST(req: Request) {
  const signature = req.headers.get("stripe-signature");

  if (!signature) {
    return new NextResponse("Missing signature", { status: 400 });
  }

  const body = await req.text();

  let event: Stripe.Event;

  // Verify the webhook really came from Stripe.
  try {
    event = stripe.webhooks.constructEvent(
      body,
      signature,
      process.env.STRIPE_WEBHOOK_SECRET!
    );
  } catch (error) {
    console.error("Webhook signature verification failed:", error);

    return new NextResponse("Invalid signature", {
      status: 400,
    });
  }

  if (event.type !== "checkout.session.completed") {
    return NextResponse.json({ received: true });
  }

  try {
    const session = event.data.object as Stripe.Checkout.Session;

    // Do not mark an unpaid session as paid.
    if (session.payment_status !== "paid") {
      console.log("Skipping unpaid checkout session:", session.id);

      return NextResponse.json({ received: true });
    }

    const userId = session.metadata?.user_id;
    const cartRaw = session.metadata?.cart;

    if (!userId || !cartRaw) {
      console.error("Missing checkout metadata:", session.id);

      return NextResponse.json(
        { error: "Missing checkout metadata" },
        { status: 400 }
      );
    }

    // Check whether this Stripe session was already processed.
    const { data: existingOrder, error: lookupError } =
      await supabaseAdmin
        .from("orders")
        .select("id")
        .eq("stripe_session_id", session.id)
        .maybeSingle();

    if (lookupError) {
      console.error("Order lookup failed:", lookupError);

      return NextResponse.json(
        { error: "Failed to check order" },
        { status: 500 }
      );
    }

    if (existingOrder) {
      return NextResponse.json({ received: true });
    }

    const cart = JSON.parse(cartRaw) as CartItem[];

    if (
      !Array.isArray(cart) ||
      cart.length === 0 ||
      cart.some(
        (item) =>
          !Number.isSafeInteger(item.id) ||
          item.id <= 0 ||
          typeof item.name !== "string" ||
          !Number.isFinite(item.price) ||
          item.price <= 0 ||
          !Number.isSafeInteger(item.quantity) ||
          item.quantity <= 0
      )
    ) {
      console.error("Invalid cart metadata:", session.id);

      return NextResponse.json(
        { error: "Invalid cart metadata" },
        { status: 400 }
      );
    }

    // Calculate totals in integer cents.
    const subtotalCents = cart.reduce(
      (sum, item) =>
        sum + Math.round(item.price * 100) * item.quantity,
      0
    );

    const taxCents = Math.round(subtotalCents * 0.13);
    const expectedTotalCents = subtotalCents + taxCents;

    if (
      session.currency?.toLowerCase() !== "cad" ||
      session.amount_total !== expectedTotalCents
    ) {
      console.error("Checkout total mismatch:", {
        sessionId: session.id,
        expectedTotalCents,
        actualTotalCents: session.amount_total,
      });

      return NextResponse.json(
        { error: "Checkout total mismatch" },
        { status: 400 }
      );
    }

    const subtotal = subtotalCents / 100;
    const tax = taxCents / 100;
    const total = expectedTotalCents / 100;

    // Atomically save the order and its items.
    const { data: orderId, error: orderError } =
      await supabaseAdmin.rpc("create_stripe_order", {
        p_user_id: userId,
        p_stripe_session_id: session.id,
        p_subtotal: subtotal,
        p_tax: tax,
        p_total: total,
        p_customer_name:
          session.customer_details?.name ?? null,
        p_customer_email:
          session.customer_details?.email ?? null,
        p_customer_phone:
          session.customer_details?.phone ?? null,
        p_shipping_address:
          session.customer_details?.address ?? null,
        p_items: cart,
      });

    if (orderError) {
      // A simultaneous webhook delivery may have
      // inserted this session first.
      if (orderError.code === "23505") {
        const { data: duplicate, error: duplicateError } =
          await supabaseAdmin
            .from("orders")
            .select("id")
            .eq("stripe_session_id", session.id)
            .maybeSingle();

        if (!duplicateError && duplicate) {
          return NextResponse.json({ received: true });
        }
      }

      console.error("Atomic order creation failed:", orderError);

      return NextResponse.json(
        { error: "Failed to save order" },
        { status: 500 }
      );
    }

    // Send an email notification to the store.
    // Email failures must not undo a paid order.
    try {
      const address = session.customer_details?.address;

      const escapeHtml = (value: unknown) =>
        String(value ?? "")
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;")
          .replace(/'/g, "&#39;");

      const { error: emailError } = await resend.emails.send({
        from: process.env.STORE_EMAIL!,
        to: process.env.ADMIN_EMAIL!,
        subject: `New order #${orderId}`,
        html: `
          <h2>New Order #${orderId}</h2>

          <p><strong>Subtotal:</strong> $${subtotal.toFixed(2)} CAD</p>
          <p><strong>HST:</strong> $${tax.toFixed(2)} CAD</p>
          <p><strong>Total:</strong> $${total.toFixed(2)} CAD</p>

          <h3>Customer</h3>
          <p><strong>Name:</strong> ${escapeHtml(session.customer_details?.name)}</p>
          <p><strong>Email:</strong> ${escapeHtml(session.customer_details?.email)}</p>
          <p><strong>Phone:</strong> ${escapeHtml(session.customer_details?.phone)}</p>

          <h3>Shipping Address</h3>
          <p>
            ${escapeHtml(address?.line1)}<br />
            ${escapeHtml(address?.line2)}<br />
            ${escapeHtml(address?.city)},
            ${escapeHtml(address?.state)}
            ${escapeHtml(address?.postal_code)}<br />
            ${escapeHtml(address?.country)}
          </p>

          <h3>Items</h3>
          <ul>
            ${cart
              .map(
                (item) =>
                  `<li>${escapeHtml(item.name)} × ${
                    item.quantity
                  } — $${item.price.toFixed(2)} CAD</li>`
              )
              .join("")}
          </ul>
        `,
      });

      if (emailError) {
        console.error("Order notification email failed:", emailError);
      }
    } catch (emailError) {
      console.error("Order notification email failed:", emailError);
    }

    return NextResponse.json({ received: true });
  } catch (error) {
    console.error("Stripe webhook processing failed:", error);

    return NextResponse.json(
      { error: "Webhook processing failed" },
      { status: 500 }
    );
  }
}
