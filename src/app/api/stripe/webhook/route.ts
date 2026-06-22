import { NextResponse } from "next/server";
import Stripe from "stripe";
import { stripe } from "../../../lib/stripe";
import { supabaseAdmin } from "../../../lib/supabaseAdmin";
import { resend } from "../../../lib/email";

export async function POST(req: Request) {
  const signature = req.headers.get("stripe-signature");

  if (!signature) {
    return new NextResponse("Missing signature", { status: 400 });
  }

  const body = await req.text();

  let event: Stripe.Event;

  try {
    event = stripe.webhooks.constructEvent(
      body,
      signature,
      process.env.STRIPE_WEBHOOK_SECRET!
    );
  } catch (err) {
    console.error("Webhook signature verification failed:", err);
    return new NextResponse("Invalid signature", { status: 400 });
  }

  if (event.type === "checkout.session.completed") {
    const session = event.data.object as Stripe.Checkout.Session;

    const userId = session.metadata?.user_id;
    const cartRaw = session.metadata?.cart;

    if (!userId || !cartRaw) {
      return NextResponse.json(
        { error: "Missing metadata" },
        { status: 400 }
      );
    }

    const { data: existingOrder, error: existingOrderError } =
      await supabaseAdmin
        .from("orders")
        .select("id")
        .eq("stripe_session_id", session.id)
        .maybeSingle();

    if (existingOrderError) {
      console.error("Existing order check error:", existingOrderError);
      return NextResponse.json(
        { error: "Failed to check existing order" },
        { status: 500 }
      );
    }

    if (existingOrder) {
      return NextResponse.json({ received: true });
    }

    const cart = JSON.parse(cartRaw) as Array<{
      id: number;
      name: string;
      price: number;
      quantity: number;
    }>;

    const subtotal = cart.reduce((sum, item) => {
      return sum + item.price * item.quantity;
    }, 0);

    const tax = subtotal * 0.13;

    const total =
      typeof session.amount_total === "number"
        ? session.amount_total / 100
        : subtotal + tax;

    const { data: orderData, error: orderError } = await supabaseAdmin
      .from("orders")
      .insert({
        user_id: userId,
        subtotal,
        tax,
        total,
        status: "paid",
        stripe_session_id: session.id,
        customer_name: session.customer_details?.name ?? null,
        customer_email: session.customer_details?.email ?? null,
        customer_phone: session.customer_details?.phone ?? null,
        shipping_address: session.customer_details?.address ?? null,
      })
      .select()
      .single();

    if (orderError || !orderData) {
      console.error("Order insert error:", orderError);
      return NextResponse.json(
        { error: "Failed to create order" },
        { status: 500 }
      );
    }

    const itemsToInsert = cart.map((item) => ({
      order_id: orderData.id,
      product_id: item.id,
      product_name: item.name,
      price: item.price,
      quantity: item.quantity,
    }));

    const { error: itemsError } = await supabaseAdmin
      .from("order_items")
      .insert(itemsToInsert);

    if (itemsError) {
      console.error("Order items insert error:", itemsError);
      return NextResponse.json(
        { error: "Failed to create order items" },
        { status: 500 }
      );
    }

    try {
      const address = session.customer_details?.address;

      await resend.emails.send({
        from: process.env.STORE_EMAIL!,
        to: process.env.ADMIN_EMAIL!,
        subject: `New order #${orderData.id}`,
        html: `
          <h2>New Order #${orderData.id}</h2>

          <p><strong>Subtotal:</strong> $${subtotal.toFixed(2)} CAD</p>
          <p><strong>HST:</strong> $${tax.toFixed(2)} CAD</p>
          <p><strong>Total:</strong> $${total.toFixed(2)} CAD</p>

          <h3>Customer</h3>
          <p>
            <strong>Name:</strong> ${
              session.customer_details?.name ?? "N/A"
            }<br />
            <strong>Email:</strong> ${
              session.customer_details?.email ?? "N/A"
            }<br />
            <strong>Phone:</strong> ${
              session.customer_details?.phone ?? "N/A"
            }
          </p>

          <h3>Shipping Address</h3>
          <p>
            ${address?.line1 ?? ""}<br />
            ${address?.line2 ?? ""}<br />
            ${address?.city ?? ""}, ${address?.state ?? ""} ${
              address?.postal_code ?? ""
            }<br />
            ${address?.country ?? ""}
          </p>

          <h3>Items</h3>
          <ul>
            ${cart
              .map(
                (item) =>
                  `<li>${item.name} × ${
                    item.quantity
                  } — $${Number(item.price).toFixed(2)} CAD</li>`
              )
              .join("")}
          </ul>
        `,
      });
    } catch (emailError) {
      console.error("Email notification failed:", emailError);
    }
  }

  return NextResponse.json({ received: true });
}
