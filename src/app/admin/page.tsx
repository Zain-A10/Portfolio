"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { supabase } from "../lib/supabase";
import CopyButton from "../components/CopyButton";

type ShippingAddress = {
  line1?: string;
  line2?: string | null;
  city?: string;
  state?: string;
  postal_code?: string;
  country?: string;
};

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
  user_id: string;
  customer_name: string | null;
  customer_email: string | null;
  customer_phone: string | null;
  shipping_address: ShippingAddress | null;
  order_items: OrderItem[];
};

const STATUS_OPTIONS = ["paid", "processing", "shipped", "delivered"];

function formatAddress(address: ShippingAddress | null) {
  if (!address) return "No shipping address saved.";

  return [
    address.line1,
    address.line2,
    `${address.city ?? ""}, ${address.state ?? ""} ${
      address.postal_code ?? ""
    }`.trim(),
    address.country,
  ]
    .filter(Boolean)
    .join("\n");
}

function getStatusStyles(status: string) {
  switch (status) {
    case "paid":
      return "bg-gray-100 text-gray-700";
    case "processing":
      return "bg-blue-100 text-blue-700";
    case "shipped":
      return "bg-orange-100 text-orange-700";
    case "delivered":
      return "bg-green-100 text-green-700";
    default:
      return "bg-gray-100 text-gray-700";
  }
}

function escapeCsv(value: string | number | null | undefined) {
  const stringValue = String(value ?? "");
  return `"${stringValue.replace(/"/g, '""')}"`;
}

function downloadOrdersCsv(orders: Order[]) {
  const headers = [
    "Order ID",
    "Date",
    "Status",
    "Subtotal",
    "Tax",
    "Total",
    "Customer Name",
    "Customer Email",
    "Customer Phone",
    "Shipping Address",
    "Items",
  ];

  const rows = orders.map((order) => {
    const items = order.order_items
      ?.map(
        (item) =>
          `${item.product_name} x${item.quantity} @ $${Number(
            item.price
          ).toFixed(2)}`
      )
      .join("; ");

    return [
      order.id,
      new Date(order.created_at).toLocaleString(),
      order.status,
      Number(order.subtotal ?? 0).toFixed(2),
      Number(order.tax ?? 0).toFixed(2),
      Number(order.total).toFixed(2),
      order.customer_name,
      order.customer_email,
      order.customer_phone,
      formatAddress(order.shipping_address).replace(/\n/g, ", "),
      items,
    ];
  });

  const csv = [
    headers.map(escapeCsv).join(","),
    ...rows.map((row) => row.map(escapeCsv).join(",")),
  ].join("\n");

  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);

  const link = document.createElement("a");
  link.href = url;
  link.download = `orders-${new Date().toISOString().slice(0, 10)}.csv`;
  link.click();

  URL.revokeObjectURL(url);
}

export default function AdminPage() {
  const [orders, setOrders] = useState<Order[]>([]);
  const [message, setMessage] = useState("Loading...");
  const [isAdmin, setIsAdmin] = useState<boolean | null>(null);
  const [statusFilter, setStatusFilter] = useState("all");

  useEffect(() => {
    async function loadPage() {
      const {
        data: { user },
        error: userError,
      } = await supabase.auth.getUser();

      if (userError || !user) {
        setIsAdmin(false);
        setMessage("Please log in first.");
        return;
      }

      const { data: profile } = await supabase
        .from("profiles")
        .select("is_admin")
        .eq("id", user.id)
        .single();

      if (!profile?.is_admin) {
        setIsAdmin(false);
        setMessage("You do not have access to this page.");
        return;
      }

      setIsAdmin(true);

      const { data, error } = await supabase
        .from("orders")
        .select(`
          id,
          subtotal,
          tax,
          total,
          status,
          created_at,
          user_id,
          customer_name,
          customer_email,
          customer_phone,
          shipping_address,
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
      setMessage(data && data.length === 0 ? "No orders found." : "");
    }

    loadPage();
  }, []);

  async function handleStatusChange(orderId: number, newStatus: string) {
    await supabase
      .from("orders")
      .update({ status: newStatus })
      .eq("id", orderId);

    setOrders((prev) =>
      prev.map((order) =>
        order.id === orderId ? { ...order, status: newStatus } : order
      )
    );
  }

  if (isAdmin === false) {
    return <p className="p-6">{message}</p>;
  }

  const filteredOrders =
    statusFilter === "all"
      ? orders
      : orders.filter((o) => o.status === statusFilter);

  return (
    <main className="mx-auto max-w-6xl px-6 py-10">
      <h1 className="text-3xl font-bold">Admin Orders</h1>

      <Link
        href="/admin/products"
        className="mt-4 inline-block rounded-full border px-4 py-2 text-sm hover:bg-gray-50"
      >
        Manage Products
      </Link>

      <div className="mt-4 flex gap-3">
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="border px-3 py-2"
        >
          <option value="all">All</option>
          {STATUS_OPTIONS.map((s) => (
            <option key={s}>{s}</option>
          ))}
        </select>

        <button
          onClick={() => downloadOrdersCsv(filteredOrders)}
          className="border px-4 py-2"
        >
          Export CSV
        </button>
      </div>

      <div className="mt-6 space-y-6">
        {filteredOrders.map((order) => {
          const address = formatAddress(order.shipping_address);

          return (
            <div key={order.id} className="rounded-xl border p-6">
              <div className="flex items-center justify-between">
                <h2 className="font-semibold">Order #{order.id}</h2>

                <span
                  className={`rounded px-2 py-1 text-sm ${getStatusStyles(
                    order.status
                  )}`}
                >
                  {order.status}
                </span>
              </div>

              <p className="mt-2 text-sm text-gray-600">
                Subtotal: ${Number(order.subtotal ?? 0).toFixed(2)} CAD
              </p>

              <p className="text-sm text-gray-600">
                Tax: ${Number(order.tax ?? 0).toFixed(2)} CAD
              </p>

              <p className="font-bold">
                Total: ${Number(order.total).toFixed(2)} CAD
              </p>

              <select
                value={order.status}
                onChange={(e) =>
                  handleStatusChange(order.id, e.target.value)
                }
                className="mt-2 border px-2 py-1"
              >
                {STATUS_OPTIONS.map((s) => (
                  <option key={s}>{s}</option>
                ))}
              </select>

              <div className="mt-4">
                <h3 className="font-semibold">Customer</h3>
                <p>{order.customer_name}</p>
                <p>{order.customer_email}</p>
                <p>{order.customer_phone}</p>
              </div>

              <div className="mt-4">
                <div className="flex items-center justify-between">
                  <h3 className="font-semibold">Shipping</h3>
                  <CopyButton text={address} />
                </div>
                <pre className="mt-1 text-sm">{address}</pre>
              </div>

              <div className="mt-4">
                <h3 className="font-semibold">Items</h3>
                {order.order_items.map((item) => (
                  <div key={item.id}>
                    {item.product_name} × {item.quantity}
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </main>
  );
}