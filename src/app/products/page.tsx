import ProductList from "../components/ProductList";
import { supabase } from "../lib/supabase";
import { Product } from "../components/ProductCard";

export default async function ProductsPage() {
  const { data, error } = await supabase
    .from("products")
    .select("*")
    .order("created_at", { ascending: false });

  if (error) {
    return (
      <main className="mx-auto max-w-6xl px-6 py-10">
        <h1 className="mb-6 text-3xl font-bold">Products</h1>
        <p className="text-red-600">Failed to load products.</p>
      </main>
    );
  }

  const products = (data || []) as Product[];

  return (
    <main className="mx-auto max-w-6xl px-6 py-10">
      <div className="mb-8">
        <p className="text-sm font-semibold uppercase tracking-[0.2em] text-gray-500">
          Catalog
        </p>
        <h1 className="mt-2 text-3xl font-bold tracking-tight">Products</h1>
        <p className="mt-2 text-gray-600">
          Browse the current catalog and find the right product quickly.
        </p>
      </div>

      <ProductList products={products} />
    </main>
  );
}