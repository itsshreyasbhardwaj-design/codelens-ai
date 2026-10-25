'use client';
import { useEffect, useState } from 'react';

interface OrderView {
  id: string;
  total: number;
  /** DEFECT (frontend/backend contract break): GET /api/orders/[id] returns
   *  only { id, total, items }. customerName and shippedAt are never sent, so
   *  both render as undefined. */
  customerName: string;
  shippedAt: string;
  items: Array<{ id: string; quantity: number }>;
}

export function OrderSummary({ orderId }: { orderId: string }) {
  const [order, setOrder] = useState<OrderView | null>(null);

  useEffect(() => {
    // DEFECT (unhandled rejection): no catch, so a failed request produces an
    // unhandled promise rejection and the component sits empty forever.
    fetch(`/api/orders/${orderId}`)
      .then((r) => r.json())
      .then(setOrder);
  }, [orderId]);

  if (!order) return null;

  return (
    <section>
      <h2>Order {order.id}</h2>
      <p>Customer: {order.customerName}</p>
      <p>Shipped: {order.shippedAt}</p>
      <p>Total: {order.total / 100}</p>
    </section>
  );
}
