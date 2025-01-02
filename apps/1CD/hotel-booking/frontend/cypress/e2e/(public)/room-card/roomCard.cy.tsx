describe('HotelDetail', () => {
  beforeEach(() => {
    cy.visit('/hotel-detail/674bfbd6a111c70660b55541');
  });
  it('1. should render', () => {
    cy.scrollTo('bottom').should('exist', '[data-cy="Show-More"]');
    cy.get('[data-cy="Show-More"]').first().click();
    cy.get('[data-cy="Hotel-Room-Detail"]').should('exist');
    cy.get('[data-cy="Room-Dialog-Close" ]').first().click({ force: true }).should('not.exist');
  });
  it('2. should render', () => {
    cy.get('[data-cy="Show-More"]').first().click();
    cy.get('[data-cy="Hotel-Room-Detail"]').should('exist');
    cy.get('[data-cy="HotelRoomCarousel"]').should('exist');
    cy.get('[data-cy="next-image"]').click();
    cy.get('[data-cy=carousel-item1]').should('be.visible');
    cy.get('[data-cy="previos-image"]').click();
    cy.get('[data-cy=carousel-item0]').should('be.visible');
  });
  it('3. should render', () => {
    cy.get('[data-cy="Hotel-Detail-Page"]').should('be.visible');
    cy.scrollTo('bottom').should('exist', '[data-cy="Hotel-Rooms"]');
    cy.get('[data-cy="All-Rooms-button"]').click();
    cy.get('[data-cy=one-button]').click();
  });
  it('4. should render', () => {
    cy.get('[data-cy="Price-Detail-Button"]').last().click({ force: true });
    cy.get('[data-cy="Price-Detail-Dialog"]').should('exist');
    cy.get('[data-cy="Price-Detail-Dialog-Close"]').last().click().should('not.exist');
  });
  it('5. should render', () => {
    cy.get('[data-cy="Reserve-button"]').first().click();
    cy.visit('/checkout/674851d9066230f0d7f74866').should('exist');
  });
});
