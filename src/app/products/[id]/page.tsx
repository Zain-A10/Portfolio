import { supabase } from "../../lib/supabase";
import Image from "next/image";
import Link from "next/link";
import AddToCartButton from "../../components/AddToCartButton";

type Product = {
  id: number;
  name: string;
  description: string | null;
  price: number;
  image_url: string | null;
  category: string | null;
  in_stock: boolean;
};

type ProductPageProps = {
  params: Promise<{ id: string }>;
};

export default async function ProductPage({ params }: ProductPageProps) {
  const { id } = await params;
  const productId = Number(id);

  if (Number.isNaN(productId)) {
    return <div className="p-6">Invalid product.</div>;
  }

  const { data, error } = await supabase
    .from("products")
    .select("*")
    .eq("id", productId)
    .maybeSingle();

  if (error || !data) {
    return <div className="p-6">Product not found.</div>;
  }

  const product = data as Product;

  return (
    <main className="mx-auto max-w-6xl px-6 py-10">
      <Link href="/products" className="mb-6 inline-block text-sm text-gray-600">
        ← Back to products
      </Link>

      <div className="grid gap-10 md:grid-cols-2">
        <div className="flex h-\[450px]\ w-full items-center justify-center overflow-hidden rounded-xl bg-white p-6">
          {product.image_url ? (
            <Image
              src={product.image_url}
              alt={product.name}
              width={800}
              height={800}
              className="max-h-full w-auto object-contain"
            />
          ) : (
            <div className="flex h-full items-center justify-center text-sm text-gray-500">
              No image
            </div>
          )}
        </div>

        <div>
          {product.category && (
            <p className="text-xs font-semibold uppercase tracking-[0.2em] text-gray-500">
              {product.category}
            </p>
          )}

          <h1 className="mt-2 text-3xl font-bold">{product.name}</h1>

          <p className="mt-4 text-2xl font-semibold">
            ${Number(product.price).toFixed(2)} CAD
          </p>

          {product.description && (
            <p className="mt-4 text-gray-600">{product.description}</p>
          )}

          <p
            className={`mt-4 text-sm font-medium ${
              product.in_stock ? "text-green-600" : "text-red-600"
            }`}
          >
            {product.in_stock ? "In Stock" : "Out of Stock"}
          </p>

          <div className="mt-6">
            <AddToCartButton
              product={{
                id: product.id,
                name: product.name,
                price: Number(product.price),
              }}
              inStock={product.in_stock}
            />
          </div>
        </div>
      </div>
    </main>
  );
}