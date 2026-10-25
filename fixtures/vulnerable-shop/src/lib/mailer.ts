// DEFECT (integration implemented but never invoked): nothing in the codebase
// imports or calls sendOrderConfirmation, so customers never get an email.
export async function sendOrderConfirmation(email: string, orderId: string): Promise<void> {
  await fetch('https://api.mailprovider.test/v1/send', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ to: email, template: 'order_confirmation', orderId }),
  });
}
