import { listAllProducts } from '../../lib/db';

export default async function ProductsPage() {
  // DEFECT (missing loading and error states): a slow or failing query renders
  // nothing and shows the user no feedback at all.
  const products = await listAllProducts();

  return (
    <div>
      <h1>Products</h1>
      {products.map((p: any) => (
        <div key={p.id}>
          {/* DEFECT (missing alt text): screen readers announce nothing here. */}
          <img src={`/img/${p.id}.jpg`} width={200} height={200} />
          <h2>{p.name}</h2>
          {/* DEFECT (XSS): a product description is rendered as raw HTML, so
              stored markup from the admin form executes in the browser. */}
          <div dangerouslySetInnerHTML={{ __html: p.description }} />
          {/* DEFECT (unlabelled control): an icon-only button with no
              accessible name. */}
          <button onClick={() => {}}>🛒</button>
        </div>
      ))}
    </div>
  );
}
