"use client";

import Image from "next/image";
import Link from "next/link";
import { useCart } from "./CartProvider";

export type Product = {
  id: number;
  name: string;
  description: string | null;
  price: number;
  image_url: string | null;
  category: string | null;
  in_stock: boolean;
};

type ProductCardProps = {
  product: Product;
};

export default function ProductCard({ product }: ProductCardProps) {
  const { addToCart } = useCart();

  return (
    <div className="overflow-hidden rounded-xl border bg-white shadow-sm">
      <Link href={`/products/${product.id}`} className="block">
        <div className="relative h-56 w-full bg-gray-100">
          {product.image_url ? (
            <Image
              src={product.image_url}
              alt={product.name}
              fill
              className="object-contain"
            />
          ) : (
            <div className="flex h-full items-center justify-center text-sm text-gray-500">
              No image
            </div>
          )}
        </div>
      </Link>

      <div className="p-4">
        {product.category && (
          <p className="mb-2 text-xs font-medium uppercase tracking-wide text-gray-500">
            {product.category}
          </p>
        )}

        <Link href={`/products/${product.id}`}>
          <h2 className="text-lg font-semibold hover:underline">
            {product.name}
          </h2>
        </Link>

        {product.description && (
          <p className="mt-2 text-sm text-gray-600">{product.description}</p>
        )}

        <p className="mt-3 text-base font-bold">
          ${Number(product.price).toFixed(2)} CAD
        </p>

        <button
          onClick={() =>
            addToCart({
              id: product.id,
              name: product.name,
              price: Number(product.price),
            })
          }
          disabled={!product.in_stock}
          className="mt-4 w-full rounded bg-black px-4 py-2 text-white disabled:cursor-not-allowed disabled:opacity-50"
        >
          {product.in_stock ? "Add to Cart" : "Out of Stock"}
        </button>
      </div>
    </div>
  );
}