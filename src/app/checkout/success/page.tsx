import ClearCart from "./ClearCart";
import Link from "next/link";

type SuccessPageProps = {
  searchParams: Promise<{
    session_id?: string;
  }>;
};

export default async function CheckoutSuccessPage({
  searchParams,
}: SuccessPageProps) {
  const { session_id } = await searchParams;

  return (
    <main className="mx-auto max-w-3xl px-6 py-12 text-center">
      <ClearCart />

      <h1 className="text-3xl font-bold">Payment successful</h1>

      <p className="mt-4 text-gray-600">
        Thanks for your order. Your payment has been processed successfully.
      </p>

      {session_id && (
        <p className="mt-2 text-sm text-gray-500">Session ID: {session_id}</p>
      )}

      <div className="mt-8 flex justify-center gap-4">
        <Link
          href="/products"
          className="rounded-full bg-black px-6 py-3 text-white hover:opacity-90"
        >
          Continue Shopping
        </Link>

        <Link
          href="/orders"
          className="rounded-full border px-6 py-3 hover:bg-gray-50"
        >
          View Orders
        </Link>
      </div>
    </main>
  );
}