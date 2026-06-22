"use client";

import { useEffect, useState } from "react";
import { supabase } from "../lib/supabase";

type OrderItem = {
  id: number;
  product_name: string;
  price: number;
  quantity: number;
};

type Order = {
  id: number;
  subtotal: number | null;
  tax: number | null;
  total: number;
  status: string;
  created_at: string;
  order_items: OrderItem[];
};

export default function OrdersPage() {
  const [orders, setOrders] = useState<Order[]>([]);
  const [message, setMessage] = useState("Loading...");

  useEffect(() => {
    async function loadOrders() {
      const {
        data: { user },
      } = await supabase.auth.getUser();

      if (!user) {
        setMessage("Please log in to view your orders.");
        return;
      }

      const { data, error } = await supabase
        .from("orders")
        .select(`
          id,
          subtotal,
          tax,
          total,
          status,
          created_at,
          order_items (
            id,
            product_name,
            price,
            quantity
          )
        `)
        .order("created_at", { ascending: false });

      if (error) {
        setMessage(error.message);
        return;
      }

      setOrders((data as Order[]) || []);
      setMessage(data && data.length === 0 ? "No orders yet." : "");
    }

    loadOrders();
  }, []);

  return (
    <main className="p-6">
      <h1 className="text-2xl font-bold">My Orders</h1>

      {message && <p className="mt-4 text-gray-600">{message}</p>}

      <div className="mt-6 space-y-4">
        {orders.map((order) => (
          <div key={order.id} className="rounded-lg border p-4">
            <p className="font-semibold">Order #{order.id}</p>

            <p className="text-sm text-gray-600">
              Subtotal: ${Number(order.subtotal ?? 0).toFixed(2)} CAD
            </p>
            <p className="text-sm text-gray-600">
              HST: ${Number(order.tax ?? 0).toFixed(2)} CAD
            </p>
            <p className="text-sm text-gray-600">
              Total: ${Number(order.total).toFixed(2)} CAD
            </p>
            <p className="text-sm text-gray-600">Status: {order.status}</p>
            <p className="text-sm text-gray-600">
              Placed: {new Date(order.created_at).toLocaleString()}
            </p>

            <div className="mt-4 space-y-2">
              {order.order_items?.map((item) => (
                <div
                  key={item.id}
                  className="rounded-md bg-gray-50 px-3 py-2 text-sm"
                >
                  {item.product_name} — ${Number(item.price).toFixed(2)} CAD ×{" "}
                  {item.quantity}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </main>
  );
}