"use client";

import { FormEvent, useEffect, useState } from "react";
import Link from "next/link";
import { supabase } from "../../lib/supabase";

type Product = {
  id: number;
  name: string;
  description: string | null;
  price: number;
  image_url: string | null;
  category: string | null;
  in_stock: boolean;
};

export default function AdminProductsPage() {
  const [isAdmin, setIsAdmin] = useState<boolean | null>(null);
  const [products, setProducts] = useState<Product[]>([]);
  const [message, setMessage] = useState("Loading...");
  const [isSaving, setIsSaving] = useState(false);
  const [deletingId, setDeletingId] = useState<number | null>(null);

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [price, setPrice] = useState("");
  const [imageUrl, setImageUrl] = useState("");
  const [imageFile, setImageFile] = useState<File | null>(null);
  const [category, setCategory] = useState("");
  const [inStock, setInStock] = useState(true);
  const [editingId, setEditingId] = useState<number | null>(null);

  async function loadProducts() {
    const { data, error } = await supabase
      .from("products")
      .select("*")
      .order("created_at", { ascending: false });

    if (error) {
      setMessage(error.message);
      return;
    }

    setProducts((data as Product[]) || []);
    setMessage(data && data.length === 0 ? "No products yet." : "");
  }

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

      const { data: profile, error: profileError } = await supabase
        .from("profiles")
        .select("is_admin")
        .eq("id", user.id)
        .single();

      if (profileError || !profile?.is_admin) {
        setIsAdmin(false);
        setMessage("You do not have access to this page.");
        return;
      }

      setIsAdmin(true);
      await loadProducts();
    }

    loadPage();
  }, []);

  function resetForm() {
    setName("");
    setDescription("");
    setPrice("");
    setImageUrl("");
    setImageFile(null);
    setCategory("");
    setInStock(true);
    setEditingId(null);
  }

  async function uploadImage(file: File) {
    const fileExt = file.name.split(".").pop();
    const fileName = `${Date.now()}-${Math.random()
      .toString(36)
      .slice(2)}.${fileExt}`;
    const filePath = `products/${fileName}`;

    const { error: uploadError } = await supabase.storage
      .from("product-images")
      .upload(filePath, file, {
        cacheControl: "3600",
        upsert: false,
        contentType: file.type,
      });

    if (uploadError) {
      console.error("Upload error:", uploadError);
      throw new Error(uploadError.message);
    }

    const { data } = supabase.storage
      .from("product-images")
      .getPublicUrl(filePath);

    return data.publicUrl;
  }

  async function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setMessage("");

    const parsedPrice = Number(price);

    if (!name.trim()) {
      setMessage("Product name is required.");
      return;
    }

    if (Number.isNaN(parsedPrice) || parsedPrice <= 0) {
      setMessage("Enter a valid price.");
      return;
    }

    setIsSaving(true);

    try {
      let finalImageUrl = imageUrl.trim() || null;

      if (imageFile) {
        finalImageUrl = await uploadImage(imageFile);
      }

      if (editingId) {
        const { error } = await supabase
          .from("products")
          .update({
            name: name.trim(),
            description: description.trim() || null,
            price: parsedPrice,
            image_url: finalImageUrl,
            category: category.trim() || null,
            in_stock: inStock,
          })
          .eq("id", editingId);

        if (error) {
          console.error("Product update error:", error);
          throw new Error(error.message);
        }

        setMessage("Product updated.");
      } else {
        const { error } = await supabase.from("products").insert({
          name: name.trim(),
          description: description.trim() || null,
          price: parsedPrice,
          image_url: finalImageUrl,
          category: category.trim() || null,
          in_stock: inStock,
        });

        if (error) {
          console.error("Product insert error:", error);
          throw new Error(error.message);
        }

        setMessage("Product created.");
      }

      resetForm();
      await loadProducts();
    } catch (err) {
      console.error("Save product failed:", err);
      setMessage(err instanceof Error ? err.message : "Something went wrong.");
    } finally {
      setIsSaving(false);
    }
  }

  function startEdit(product: Product) {
    setEditingId(product.id);
    setName(product.name);
    setDescription(product.description ?? "");
    setPrice(String(product.price));
    setImageUrl(product.image_url ?? "");
    setImageFile(null);
    setCategory(product.category ?? "");
    setInStock(product.in_stock);
    setMessage("");
  }

  async function handleDelete(productId: number) {
    const confirmed = window.confirm(
      "Are you sure you want to delete this product?"
    );

    if (!confirmed) return;

    setDeletingId(productId);
    setMessage("");

    const { error } = await supabase
      .from("products")
      .delete()
      .eq("id", productId);

    if (error) {
      console.error("Delete product error:", error);
      setMessage(error.message);
      setDeletingId(null);
      return;
    }

    if (editingId === productId) {
      resetForm();
    }

    setProducts((prev) => prev.filter((product) => product.id !== productId));
    setMessage("Product deleted.");
    setDeletingId(null);
  }

  if (isAdmin === false) {
    return (
      <main className="mx-auto max-w-3xl px-6 py-10">
        <h1 className="text-3xl font-bold">Admin Products</h1>
        <p className="mt-4 text-gray-600">{message}</p>
        <Link href="/" className="mt-6 inline-block rounded-full border px-4 py-2">
          Back Home
        </Link>
      </main>
    );
  }

  return (
    <main className="mx-auto max-w-6xl px-6 py-10">
      <div className="mb-8">
        <p className="text-sm font-semibold uppercase tracking-[0.2em] text-gray-500">
          Admin
        </p>
        <h1 className="mt-2 text-3xl font-bold tracking-tight">Products</h1>
        <p className="mt-2 text-gray-600">
          Add products, edit them, or delete test products.
        </p>
      </div>

      {message && <p className="mb-6 text-gray-600">{message}</p>}

      <div className="grid gap-8 lg:grid-cols-[380px_1fr]">
        <form
          onSubmit={handleSubmit}
          className="rounded-2xl border bg-white p-6 shadow-sm"
        >
          <h2 className="text-lg font-semibold">
            {editingId ? "Edit Product" : "New Product"}
          </h2>

          <div className="mt-4 space-y-4">
            <div>
              <label className="mb-1 block text-sm font-medium">Name</label>
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="w-full rounded-xl border px-3 py-2"
                required
              />
            </div>

            <div>
              <label className="mb-1 block text-sm font-medium">
                Description
              </label>
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                className="w-full rounded-xl border px-3 py-2"
                rows={4}
              />
            </div>

            <div>
              <label className="mb-1 block text-sm font-medium">Price</label>
              <input
                value={price}
                onChange={(e) => setPrice(e.target.value)}
                className="w-full rounded-xl border px-3 py-2"
                type="number"
                step="0.01"
                min="0"
                required
              />
            </div>

            <div>
              <label className="mb-1 block text-sm font-medium">
                Upload Image
              </label>
              <input
                type="file"
                accept="image/*"
                onChange={(e) => setImageFile(e.target.files?.[0] ?? null)}
                className="w-full rounded-xl border px-3 py-2"
              />
            </div>

            <div>
              <label className="mb-1 block text-sm font-medium">
                Or paste Image URL
              </label>
              <input
                value={imageUrl}
                onChange={(e) => setImageUrl(e.target.value)}
                className="w-full rounded-xl border px-3 py-2"
              />
            </div>

            <div>
              <label className="mb-1 block text-sm font-medium">Category</label>
              <input
                value={category}
                onChange={(e) => setCategory(e.target.value)}
                className="w-full rounded-xl border px-3 py-2"
              />
            </div>

            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={inStock}
                onChange={(e) => setInStock(e.target.checked)}
              />
              In stock
            </label>

            <div className="flex gap-3">
              <button
                type="submit"
                disabled={isSaving}
                className="rounded-full bg-black px-4 py-2 text-white disabled:opacity-50"
              >
                {isSaving
                  ? "Saving..."
                  : editingId
                  ? "Update Product"
                  : "Create Product"}
              </button>

              {editingId && (
                <button
                  type="button"
                  onClick={resetForm}
                  className="rounded-full border px-4 py-2"
                >
                  Cancel
                </button>
              )}
            </div>
          </div>
        </form>

        <div className="space-y-4">
          {products.map((product) => (
            <div
              key={product.id}
              className="rounded-2xl border bg-white p-5 shadow-sm"
            >
              <div className="flex items-start justify-between gap-4">
                <div>
                  <h3 className="text-lg font-semibold">{product.name}</h3>

                  <p className="mt-1 text-sm text-gray-600">
                    ${Number(product.price).toFixed(2)} CAD
                  </p>

                  {product.category && (
                    <p className="mt-1 text-sm text-gray-500">
                      {product.category}
                    </p>
                  )}

                  {product.description && (
                    <p className="mt-3 text-sm text-gray-600">
                      {product.description}
                    </p>
                  )}

                  <p className="mt-2 text-sm">
                    {product.in_stock ? "In Stock" : "Out of Stock"}
                  </p>
                </div>

                <div className="flex gap-2">
                  <button
                    onClick={() => startEdit(product)}
                    className="rounded-full border px-4 py-2 text-sm"
                  >
                    Edit
                  </button>

                  <button
                    onClick={() => handleDelete(product.id)}
                    disabled={deletingId === product.id}
                    className="rounded-full border px-4 py-2 text-sm text-red-600 disabled:opacity-50"
                  >
                    {deletingId === product.id ? "Deleting..." : "Delete"}
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </main>
  );
}