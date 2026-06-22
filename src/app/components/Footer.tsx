export default function Footer() {
  return (
    <footer className="mt-16 border-t bg-white">
      <div className="mx-auto grid max-w-6xl gap-8 px-6 py-10 md:grid-cols-3">
        <div>
          <h2 className="text-lg font-semibold">Cloud Co Distribution</h2>
          <p className="mt-2 text-sm text-gray-600">
            Premium products delivered across Canada.
          </p>
        </div>

        <div>
          <h3 className="text-sm font-semibold uppercase tracking-wide text-gray-500">
            Contact
          </h3>
          <p className="mt-2 text-sm text-gray-600">
            Email: support@yourstore.com
          </p>
          <p className="text-sm text-gray-600">Phone: (123) 456-7890</p>
          <p className="text-sm text-gray-600">Toronto, ON, Canada</p>
        </div>

        <div>
          <h3 className="text-sm font-semibold uppercase tracking-wide text-gray-500">
            Info
          </h3>
          <p className="mt-2 text-sm text-gray-600">Shipping Policy</p>
          <p className="text-sm text-gray-600">Refund Policy</p>
          <p className="text-sm text-gray-600">Privacy Policy</p>
        </div>
      </div>

      <div className="border-t py-4 text-center text-sm text-gray-500">
        © {new Date().getFullYear()} Cloud Co Distribution. All rights reserved.
      </div>
    </footer>
  );
}