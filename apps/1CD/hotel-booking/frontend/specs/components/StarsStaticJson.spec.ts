import { Cards, Countries, RatingStars, ReviewRating } from '@/components/StarsStaticJson';

describe('static stars', () => {
  it('Rating stars', () => {
    expect(RatingStars).toHaveLength(5);
  });
  it('Review rating stars', () => {
    expect(ReviewRating).toHaveLength(10);
  });
  it('payment card image', () => {
    expect(Cards).toHaveLength(4);
  });
  it('payment Countries', () => {
    expect(Countries).toHaveLength(3);
  });
});
