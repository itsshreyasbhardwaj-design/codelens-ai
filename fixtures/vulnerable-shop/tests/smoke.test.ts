import { priceWithDiscount } from '../src/server/legacy';

// The only test in the project: no coverage of auth, authorization, payment
// state, the webhook handler, or any API route.
test('applies a 10% discount', () => {
  expect(priceWithDiscount(1000, 'SAVE10')).toBe(900);
});
