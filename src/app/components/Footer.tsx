export default function Footer() {
  return (
    <footer className="mt-16 border-t bg-white">
      <div className="mx-auto grid max-w-6xl gap-8 px-6 py-10 md:grid-cols-3">
        <div>
          <h2 className="text-lg font-semibold">CloudCore Distribution</h2>
          <p className="mt-2 text-sm text-gray-600">
            Premium products delivered across Canada.
          </p>
        </div>

        <div>
          <h3 className="text-sm font-semibold uppercase tracking-wide text-gray-500">
            Contact
          </h3>
          <p className="mt-2 text-sm text-gray-600">
            Email: cloudcoredistribution@gmail.com
          </p>
          <p className="text-sm text-gray-600">Phone: (647) 970-6864</p>
          <p className="text-sm text-gray-600">Phone: (249) 594-8825</p>
          <p className="text-sm text-gray-600">Alliston, ON, Canada</p>
        </div>

      </div>

      <div className="border-t py-4 text-center text-sm text-gray-500">
        © {new Date().getFullYear()} CloudCore Distribution. All rights reserved.
      </div>
    </footer>
  );
}