"use client";

import { useEffect, useState } from "react";

export default function AgeGate() {
  const [isVerified, setIsVerified] = useState<boolean | null>(null);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      const verified = localStorage.getItem("age-verified");
      setIsVerified(verified === "true");
    }, 0);

    return () => window.clearTimeout(timer);
  }, []);

  function handleYes() {
    localStorage.setItem("age-verified", "true");
    setIsVerified(true);
  }

  function handleNo() {
    window.location.href = "https://www.google.com";
  }

  if (isVerified === null || isVerified === true) {
    return null;
  }

  return (
    <div className="fixed inset-0 z-\[9999]\ flex items-center justify-center bg-black/70 px-6">
      <div className="max-w-md rounded-2xl bg-white p-8 text-center shadow-xl">
        <h2 className="text-2xl font-bold">Age Verification</h2>

        <p className="mt-4 text-gray-600">
          You must be 19 years or older to continue.
        </p>

        <div className="mt-6 flex gap-3">
          <button
            onClick={handleYes}
            className="w-full rounded-full bg-black px-4 py-2 text-white"
          >
            I am 19+
          </button>

          <button
            onClick={handleNo}
            className="w-full rounded-full border px-4 py-2"
          >
            Exit
          </button>
        </div>
      </div>
    </div>
  );
}