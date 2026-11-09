
import { NextResponse } from "next/server";
import { stripe } from "../../lib/stripe";
import { supabase } from "../../lib/supabase";
import { createClient } from "@supabase/supabase-js";

export const runtime = "nodejs";

type CartItem = {
  id: number;
  name?: string;
  price?: number;
  quantity: number;
};

const supabaseAdmin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!,
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
    },
  }
);

export async function POST(req: Request) {
  try {
    // 1. Verify the customer's login.
    const authHeader = req.headers.get("authorization");

    if (!authHeader?.startsWith("Bearer ")) {
      return NextResponse.json(
        { error: "You must be logged in." },
        { status: 401 }
      );
    }

    const token = authHeader.slice(7);

    const {
      data: { user },
      error: userError,
    } = await supabase.auth.getUser(token);

    if (userError || !user) {
      return NextResponse.json(
        { error: "Invalid or expired login." },
        { status: 401 }
      );
    }

    // 2. Read the cart from the browser.
    const body = await req.json();
    const cart = body.cart as CartItem[];

    if (!Array.isArray(cart) || cart.length === 0) {
      return NextResponse.json(
        { error: "Cart is empty." },
        { status: 400 }
      );
    }

    if (cart.length > 50) {
      return NextResponse.json(
        { error: "Too many cart items." },
        { status: 400 }
      );
    }

    // 3. Validate product IDs and quantities.
    const quantities = new Map<number, number>();

    for (const item of cart) {
      if (
        !item ||
        !Number.isSafeInteger(item.id) ||
        item.id <= 0 ||
        !Number.isSafeInteger(item.quantity) ||
        item.quantity < 1 ||
        item.quantity > 99
      ) {
        return NextResponse.json(
          { error: "Invalid product or quantity." },
          { status: 400 }
        );
      }

      const newQuantity =
        (quantities.get(item.id) ?? 0) + item.quantity;

      if (newQuantity > 99) {
        return NextResponse.json(
          { error: "Maximum quantity is 99 per product." },
          { status: 400 }
        );
      }

      quantities.set(item.id, newQuantity);
    }

    const productIds = Array.from(quantities.keys());

    // 4. Retrieve trusted product information.
    // Never use browser-submitted prices for payment.
    const { data: products, error: productsError } =
      await supabaseAdmin
        .from("products")
        .select("id, name, price, in_stock")
        .in("id", productIds);

    if (productsError || !products) {
      console.error("Product lookup error:", productsError);

      return NextResponse.json(
        { error: "Unable to verify products." },
        { status: 500 }
      );
    }

    if (products.length !== productIds.length) {
      return NextResponse.json(
        { error: "One or more products were not found." },
        { status: 400 }
      );
    }

    // 5. Build Stripe line items using database prices.
    let subtotalCents = 0;

    const line_items = [];
    const verifiedCart = [];

    for (const product of products) {
      if (!product.in_stock) {
        return NextResponse.json(
          { error: `${product.name} is out of stock.` },
          { status: 400 }
        );
      }

      const quantity = quantities.get(product.id)!;
      const price = Number(product.price);
      const priceCents = Math.round(price * 100);

      if (
        !Number.isFinite(price) ||
        !Number.isSafeInteger(priceCents) ||
        priceCents <= 0
      ) {
        return NextResponse.json(
          { error: `Invalid price for ${product.name}.` },
          { status: 400 }
        );
      }

      subtotalCents += priceCents * quantity;

      line_items.push({
        quantity,
        price_data: {
          currency: "cad",
          product_data: {
            name: product.name,
          },
          unit_amount: priceCents,
        },
      });

      verifiedCart.push({
        id: product.id,
        name: product.name,
        price,
        quantity,
      });
    }

    if (!Number.isSafeInteger(subtotalCents)) {
      return NextResponse.json(
        { error: "Cart total is too large." },
        { status: 400 }
      );
    }

    // 6. Calculate Ontario HST (13%).
    const taxCents = Math.round(subtotalCents * 0.13);

    if (taxCents > 0) {
      line_items.push({
        quantity: 1,
        price_data: {
          currency: "cad",
          product_data: {
            name: "HST (13%)",
          },
          unit_amount: taxCents,
        },
      });
    }

    // 7. Preserve the cart metadata for your webhook.
    const cartMetadata = JSON.stringify(verifiedCart);

    if (cartMetadata.length > 500) {
      return NextResponse.json(
        {
          error:
            "Cart is too large. Please remove some items.",
        },
        { status: 400 }
      );
    }

    const siteUrl = process.env.NEXT_PUBLIC_SITE_URL;

    if (!siteUrl) {
      throw new Error("NEXT_PUBLIC_SITE_URL is missing.");
    }

    // 8. Create the Stripe Checkout session.
    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      line_items,
      success_url: `${siteUrl}/checkout/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${siteUrl}/cart`,
      client_reference_id: user.id,
      metadata: {
        user_id: user.id,
        cart: cartMetadata,
      },
      shipping_address_collection: {
        allowed_countries: ["CA"],
      },
      phone_number_collection: {
        enabled: true,
      },
    });

    return NextResponse.json({ url: session.url });
  } catch (error) {
    console.error("Checkout error:", error);

    return NextResponse.json(
      { error: "Failed to create checkout session." },
      { status: 500 }
    );
  }
}
