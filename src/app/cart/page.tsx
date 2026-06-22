"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { useCart } from "../components/CartProvider";
import { supabase } from "../lib/supabase";

export default function CartPage() {
  const { cart, removeFromCart, clearCart } = useCart();
  const [message, setMessage] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isLoggedIn, setIsLoggedIn] = useState<boolean | null>(null);

  const subtotal = cart.reduce((sum: number, item) => {
    return sum + item.price * item.quantity;
  }, 0);

  const tax = subtotal * 0.13;
  const total = subtotal + tax;

  useEffect(() => {
    async function checkUser() {
      const {
        data: { user },
      } = await supabase.auth.getUser();

      setIsLoggedIn(!!user);
    }

    checkUser();
  }, []);

  async function handleCheckout() {
    setMessage("");

    if (cart.length === 0) {
      setMessage("Your cart is empty.");
      return;
    }

    setIsSubmitting(true);

    try {
      const {
        data: { session },
      } = await supabase.auth.getSession();

      if (!session) {
        setMessage("You must be logged in.");
        setIsSubmitting(false);
        return;
      }

      const res = await fetch("/api/checkout", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${session.access_token}`,
        },
        body: JSON.stringify({ cart }),
      });

      const data = await res.json();

      if (!res.ok) {
        setMessage(data.error || "Checkout failed.");
        setIsSubmitting(false);
        return;
      }

      window.location.href = data.url;
    } catch (error) {
      console.error(error);
      setMessage("Something went wrong.");
      setIsSubmitting(false);
    }
  }

  return (
    <main className="mx-auto max-w-4xl px-6 py-10">
      <h1 className="text-3xl font-bold">Cart</h1>

      {message && (
        <p className="mt-4 rounded-md border border-green-200 bg-green-50 px-3 py-2 text-sm text-green-700">
          {message}
        </p>
      )}

      {cart.length === 0 ? (
        <p className="mt-4 text-gray-600">Your cart is empty.</p>
      ) : (
        <div className="mt-6 space-y-4">
          {cart.map((item) => (
            <div
              key={item.id}
              className="flex items-center justify-between rounded-2xl border bg-white p-5 shadow-sm"
            >
              <div>
                <h2 className="font-semibold">{item.name}</h2>
                <p className="text-sm text-gray-600">
                  ${Number(item.price).toFixed(2)} CAD × {item.quantity}
                </p>
              </div>

              <button
                onClick={() => removeFromCart(item.id)}
                className="rounded-full border px-4 py-2 text-sm hover:bg-gray-50"
              >
                Remove
              </button>
            </div>
          ))}

          <div className="rounded-2xl border bg-white p-5 shadow-sm">
            <div className="space-y-1">
              <p className="text-sm text-gray-600">
                Subtotal: ${subtotal.toFixed(2)} CAD
              </p>
              <p className="text-sm text-gray-600">
                HST (13%): ${tax.toFixed(2)} CAD
              </p>
              <p className="text-xl font-bold">
                Total: ${total.toFixed(2)} CAD
              </p>
            </div>

            <div className="mt-4 flex flex-wrap gap-3">
              {isLoggedIn ? (
                <button
                  onClick={handleCheckout}
                  disabled={isSubmitting}
                  className="rounded-full bg-black px-5 py-2.5 text-white disabled:opacity-50"
                >
                  {isSubmitting ? "Redirecting..." : "Proceed to Payment"}
                </button>
              ) : (
                <Link
                  href="/auth"
                  className="rounded-full bg-black px-5 py-2.5 text-white"
                >
                  Log in to Checkout
                </Link>
              )}

              <button
                onClick={clearCart}
                className="rounded-full border px-5 py-2.5"
              >
                Clear Cart
              </button>
            </div>

            {isLoggedIn === false && (
              <p className="mt-3 text-sm text-gray-600">
                You need to log in before placing an order.
              </p>
            )}
          </div>
        </div>
      )}
    </main>
  );
}
