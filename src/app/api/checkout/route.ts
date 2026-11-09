
import { NextResponse } from "next/server";
import { stripe } from "../../lib/stripe";
import { supabase } from "../../lib/supabase";

type CartItem = {
  id: number;
  quantity: number;
};

type Product = {
  id: number;
  name: string;
  price: number;
  in_stock: boolean;
};

export async function POST(req: Request) {
  try {
    const body = await req.json();
    const cart = body.cart as CartItem[];

    if (!Array.isArray(cart) || cart.length === 0) {
      return NextResponse.json(
        { error: "Cart is empty." },
        { status: 400 }
      );
    }

    // Validate the cart before querying the database.
    if (
      cart.length > 50 ||
      cart.some(
        (item) =>
          !item ||
          !Number.isSafeInteger(item.id) ||
          item.id <= 0 ||
          !Number.isInteger(item.quantity) ||
          item.quantity < 1 ||
          item.quantity > 100
      )
    ) {
      return NextResponse.json(
        { error: "Invalid cart items or quantities." },
        { status: 400 }
      );
    }

    const authHeader = req.headers.get("authorization");
    const token = authHeader?.startsWith("Bearer ")
      ? authHeader.slice(7)
      : null;

    if (!token) {
      return NextResponse.json(
        { error: "You must be logged in." },
        { status: 401 }
      );
    }

    const {
      data: { user },
      error: userError,
    } = await supabase.auth.getUser(token);

    if (userError || !user) {
      return NextResponse.json(
        { error: "Invalid user." },
        { status: 401 }
      );
    }

    // Consolidate duplicate products.
    const quantities = new Map<number, number>();

    for (const item of cart) {
      const total = (quantities.get(item.id) ?? 0) + item.quantity;

      if (total > 100) {
        return NextResponse.json(
          { error: "Maximum quantity is 100 per product." },
          { status: 400 }
        );
      }

      quantities.set(item.id, total);
    }

    // Retrieve authoritative product information.
    const productIds = Array.from(quantities.keys());

    const { data, error: productsError } = await supabase
      .from("products")
      .select("id, name, price, in_stock")
      .in("id", productIds);

    if (productsError) {
      console.error("Product lookup failed:", productsError);

      return NextResponse.json(
        { error: "Unable to verify product prices." },
        { status: 500 }
      );
    }

    const products = (data ?? []) as Product[];
    const productsById = new Map(
      products.map((product) => [Number(product.id), product])
    );

    const verifiedCart: {
      id: number;
      name: string;
      price: number;
      quantity: number;
    }[] = [];

    let subtotalCents = 0;

    for (const [id, quantity] of quantities) {
      const product = productsById.get(id);

      if (!product) {
        return NextResponse.json(
          { error: `Product ${id} no longer exists.` },
          { status: 400 }
        );
      }

      if (!product.in_stock) {
        return NextResponse.json(
          { error: `${product.name} is out of stock.` },
          { status: 400 }
        );
      }

      const price = Number(product.price);
      const unitAmount = Math.round(price * 100);

      if (
        !Number.isFinite(price) ||
        price <= 0 ||
        !Number.isSafeInteger(unitAmount)
      ) {
        return NextResponse.json(
          { error: "Invalid product price." },
          { status: 500 }
        );
      }

      subtotalCents += unitAmount * quantity;

      verifiedCart.push({
        id,
        name: product.name,
        price: unitAmount / 100,
        quantity,
      });
    }

    if (!Number.isSafeInteger(subtotalCents)) {
      return NextResponse.json(
        { error: "Cart total is too large." },
        { status: 400 }
      );
    }

    const taxCents = Math.round(subtotalCents * 0.13);

    const line_items = [
      ...verifiedCart.map((item) => ({
        quantity: item.quantity,
        price_data: {
          currency: "cad",
          product_data: {
            name: item.name,
          },
          unit_amount: Math.round(item.price * 100),
        },
      })),
      {
        quantity: 1,
        price_data: {
          currency: "cad",
          product_data: {
            name: "HST (13%)",
          },
          unit_amount: taxCents,
        },
      },
    ];

    const siteUrl = process.env.NEXT_PUBLIC_SITE_URL;

    if (!siteUrl) {
      throw new Error("NEXT_PUBLIC_SITE_URL is missing.");
    }

    // Stripe metadata values have a 500-character limit.
    const cartMetadata = JSON.stringify(verifiedCart);

    if (cartMetadata.length > 500) {
      return NextResponse.json(
        { error: "Cart is too large. Please use fewer items." },
        { status: 400 }
      );
    }

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
