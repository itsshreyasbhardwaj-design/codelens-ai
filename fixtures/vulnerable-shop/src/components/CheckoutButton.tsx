'use client';

export function CheckoutButton({ orderId }: { orderId: string }) {
  // DEFECT (dead UI action): the primary call to action has no backend call
  // behind it. There is no checkout endpoint in the codebase.
  const handleCheckout = () => {
    // TODO: wire this up to the payment endpoint
  };

  return <button onClick={handleCheckout}>Pay now</button>;
}
