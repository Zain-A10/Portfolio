import { NextResponse } from "next/server";
import { stripe } from "../../lib/stripe";
import { supabase } from "../../lib/supabase";

type CartItem = {
  id: number;
  name: string;
  price: number;
  quantity: number;
};

export async function POST(req: Request) {
  try {
    const body = await req.json();
    const cart = body.cart as CartItem[];

    if (!Array.isArray(cart) || cart.length === 0) {
      return NextResponse.json({ error: "Cart is empty." }, { status: 400 });
    }

    const authHeader = req.headers.get("authorization");
    const token = authHeader?.replace("Bearer ", "");

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
      return NextResponse.json({ error: "Invalid user." }, { status: 401 });
    }

    const subtotal = cart.reduce((sum, item) => {
      return sum + item.price * item.quantity;
    }, 0);

    const tax = subtotal * 0.13;

    const line_items = [
      ...cart.map((item) => ({
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
          unit_amount: Math.round(tax * 100),
        },
      },
    ];

    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      line_items,
      success_url: `${process.env.NEXT_PUBLIC_SITE_URL}/checkout/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.NEXT_PUBLIC_SITE_URL}/cart`,
      client_reference_id: user.id,
      metadata: {
        user_id: user.id,
        cart: JSON.stringify(cart),
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
    console.error(error);
    return NextResponse.json(
      { error: "Failed to create checkout session." },
      { status: 500 }
    );
  }
}