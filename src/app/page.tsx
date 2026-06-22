import Link from "next/link";

export default function Home() {
  return (
    <main className="bg-white">
      <section className="mx-auto flex min-h-[85vh] max-w-6xl flex-col items-center justify-center px-6 text-center">
        <p className="mb-4 text-sm font-semibold uppercase tracking-[0.2em] text-gray-500">
          Modern Ecommerce Experience
        </p>

        <h1 className="max-w-4xl text-4xl font-bold tracking-tight text-black sm:text-5xl md:text-6xl">
          Premium products delivered across Canada
        </h1>

        <p className="mt-6 max-w-2xl text-base leading-7 text-gray-600 sm:text-lg">
          Browse products, create an account, manage your cart, and place orders
          through a secure checkout experience.
        </p>

        <div className="mt-8 flex flex-col gap-4 sm:flex-row">
          <Link
            href="/products"
            className="rounded-full bg-black px-6 py-3 text-white transition hover:opacity-90"
          >
            Shop Products
          </Link>

          <Link
            href="/auth"
            className="rounded-full border border-gray-300 px-6 py-3 transition hover:bg-gray-50"
          >
            Create Account
          </Link>
        </div>
      </section>

      <section className="border-t bg-gray-50">
        <div className="mx-auto grid max-w-6xl gap-6 px-6 py-16 md:grid-cols-3">
          <div className="rounded-2xl border bg-white p-6 shadow-sm">
            <h2 className="text-lg font-semibold">Product Browsing</h2>
            <p className="mt-2 text-sm leading-6 text-gray-600">
              Browse a responsive catalog with search, filters, and dedicated
              product pages.
            </p>
          </div>

          <div className="rounded-2xl border bg-white p-6 shadow-sm">
            <h2 className="text-lg font-semibold">Secure Checkout</h2>
            <p className="mt-2 text-sm leading-6 text-gray-600">
              Checkout securely with Stripe and receive order tracking through
              your account.
            </p>
          </div>

          <div className="rounded-2xl border bg-white p-6 shadow-sm">
            <h2 className="text-lg font-semibold">Canada-Wide Fulfillment</h2>
            <p className="mt-2 text-sm leading-6 text-gray-600">
              Shipping information is collected at checkout for accurate
              fulfillment.
            </p>
          </div>
        </div>
      </section>
    </main>
  );
}