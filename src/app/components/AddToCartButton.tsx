"use client";

import { useCart } from "./CartProvider";

type AddToCartButtonProps = {
  product: {
    id: number;
    name: string;
    price: number;
  };
  inStock: boolean;
};

export default function AddToCartButton({
  product,
  inStock,
}: AddToCartButtonProps) {
  const { addToCart } = useCart();

  return (
    <button
      onClick={() => addToCart(product)}
      disabled={!inStock}
      className="rounded-full bg-black px-6 py-3 text-white transition hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
    >
      {inStock ? "Add to Cart" : "Out of Stock"}
    </button>
  );
}