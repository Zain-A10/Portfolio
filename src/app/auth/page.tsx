"use client";

import { FormEvent, useState } from "react";
import { supabase } from "../lib/supabase";

export default function AuthPage() {
  const [isLogin, setIsLogin] = useState(true);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");

  async function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setMessage("");

    if (isLogin) {
      const { error } = await supabase.auth.signInWithPassword({
        email,
        password,
      });

      if (error) {
        setMessage(error.message);
        return;
      }

      setMessage("Logged in successfully.");
      setEmail("");
      setPassword("");
    } else {
      const { error } = await supabase.auth.signUp({
        email,
        password,
      });

      if (error) {
        setMessage(error.message);
        return;
      }

      setMessage("Account created. Check your email to confirm your account.");
      setEmail("");
      setPassword("");
    }
  }

  return (
    <main className="mx-auto max-w-md p-6">
      <div className="rounded-xl border p-6 shadow-sm">
        <h1 className="text-2xl font-bold">
          {isLogin ? "Login" : "Create Account"}
        </h1>

        <p className="mt-2 text-sm text-gray-600">
          {isLogin
            ? "Log in to your account."
            : "Create a new account to continue."}
        </p>

        <form onSubmit={handleSubmit} className="mt-6 space-y-4">
          <div>
            <label className="mb-1 block text-sm font-medium">Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full rounded-md border px-3 py-2 outline-none"
              placeholder="you@example.com"
              required
            />
          </div>

          <div>
            <label className="mb-1 block text-sm font-medium">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded-md border px-3 py-2 outline-none"
              placeholder="Enter your password"
              required
            />
          </div>

          <button
            type="submit"
            className="w-full rounded-md bg-black px-4 py-2 text-white"
          >
            {isLogin ? "Login" : "Create Account"}
          </button>
        </form>

        {message && <p className="mt-4 text-sm text-gray-700">{message}</p>}

        <button
          type="button"
          onClick={() => {
            setIsLogin((prev) => !prev);
            setMessage("");
          }}
          className="mt-4 text-sm underline"
        >
          {isLogin
            ? "Need an account? Sign up"
            : "Already have an account? Log in"}
        </button>
      </div>
    </main>
  );
}