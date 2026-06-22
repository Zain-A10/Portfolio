"use client";

import { useState } from "react";
import ProductCard, { Product } from "./ProductCard";

type Props = {
  products: Product[];
};

export default function ProductList({ products }: Props) {
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState("all");

  const categories = [
    "all",
    ...Array.from(new Set(products.map((p) => p.category ?? "Uncategorized"))),
  ];

  const filteredProducts = products.filter((product) => {
    const matchesSearch = product.name
      .toLowerCase()
      .includes(search.toLowerCase());

    const productCategory = product.category ?? "Uncategorized";
    const matchesCategory =
      category === "all" || productCategory === category;

    return matchesSearch && matchesCategory;
  });

  return (
    <div>
      <div className="mb-8 grid gap-4 rounded-2xl border bg-gray-50 p-4 md:grid-cols-[1fr_220px]">
        <input
          type="text"
          placeholder="Search products..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full rounded-xl border bg-white px-4 py-3 outline-none"
        />

        <select
          value={category}
          onChange={(e) => setCategory(e.target.value)}
          className="rounded-xl border bg-white px-4 py-3 outline-none"
        >
          {categories.map((cat) => (
            <option key={cat} value={cat}>
              {cat}
            </option>
          ))}
        </select>
      </div>

      {filteredProducts.length === 0 ? (
        <p className="text-gray-600">No products found.</p>
      ) : (
        <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
          {filteredProducts.map((product) => (
            <ProductCard key={product.id} product={product} />
          ))}
        </div>
      )}
    </div>
  );
}