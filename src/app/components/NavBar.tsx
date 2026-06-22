"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { supabase } from "../lib/supabase";
import { useCart } from "./CartProvider";

type SimpleUser = {
  id: string;
  email?: string;
} | null;

export default function Navbar() {
  const { cart } = useCart();
  const [user, setUser] = useState<SimpleUser>(null);
  const [isAdmin, setIsAdmin] = useState(false);

  const itemCount = cart.reduce((total, item) => total + item.quantity, 0);

  useEffect(() => {
    async function loadUserAndRole() {
      const { data, error } = await supabase.auth.getUser();

      if (error || !data.user) {
        setUser(null);
        setIsAdmin(false);
        return;
      }

      const currentUser = {
        id: data.user.id,
        email: data.user.email,
      };

      setUser(currentUser);

      const { data: profile } = await supabase
        .from("profiles")
        .select("is_admin")
        .eq("id", currentUser.id)
        .single();

      setIsAdmin(!!profile?.is_admin);
    }

    loadUserAndRole();

    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange(() => {
      loadUserAndRole();
    });

    return () => {
      subscription.unsubscribe();
    };
  }, []);

  async function handleSignOut() {
    await supabase.auth.signOut();
  }

  return (
    <nav className="sticky top-0 z-50 border-b bg-white/90 backdrop-blur">
      <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
        <Link href="/" className="text-2xl font-bold tracking-tight">
          Cloud Co Distribution
        </Link>

        <div className="flex items-center gap-6 text-sm font-medium">
          <Link href="/products" className="hover:text-gray-500">
            Products
          </Link>

          <Link href="/orders" className="hover:text-gray-500">
            Orders
          </Link>

          <Link href="/cart" className="hover:text-gray-500">
            <span suppressHydrationWarning>
              {itemCount > 0 ? `Cart (${itemCount})` : "Cart"}
            </span>
          </Link>

          {isAdmin && (
            <Link href="/admin" className="hover:text-gray-500">
              Admin
            </Link>
          )}

          {user ? (
            <div className="flex items-center gap-3">
              <span className="hidden text-sm text-gray-600 md:inline">
                {user.email}
              </span>
              <button
                onClick={handleSignOut}
                className="rounded-full border px-4 py-2 text-sm hover:bg-gray-50"
              >
                Sign Out
              </button>
            </div>
          ) : (
            <Link
              href="/auth"
              className="rounded-full bg-black px-4 py-2 text-white hover:opacity-90"
            >
              Login
            </Link>
          )}
        </div>
      </div>
    </nav>
  );
}