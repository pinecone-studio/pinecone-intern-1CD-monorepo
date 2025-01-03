describe('InputGenreWithLocation Component', () => {
  beforeEach(() => {
    cy.visit('/admin/home');

    cy.intercept('POST', '/api/graphql').as('graphqlRequest');

    cy.get('[data-testid="create-event-button"]').click();

    cy.wait('@graphqlRequest');

    cy.get('[data-testid="venue-select-container"]').should('be.visible');
    cy.get('[data-testid="category-select-container"]').should('be.visible');
    cy.get('[data-testid="venue-select"]').should('be.visible');
    cy.get('[data-testid="category-button"]').should('be.visible');
  });

  it('should open the venue select dropdown and select an option', () => {
    cy.get('[data-testid="venue-select"]').should('be.visible');
    cy.get('[data-testid="venue-select"]').click();
    cy.get('[data-testid="arena-item-0"]').should('be.visible');
    cy.get('[data-testid="arena-item-1"]').should('be.visible');
    cy.get('[data-testid="arena-item-1"]').click();
    cy.get('[data-testid="venue-select"]').should('contain.text', 'UG-arena');
  });

  it('should open the category select dropdown and select an option', () => {
    cy.get('[data-testid="category-button"]').should('be.visible');

    cy.get('[data-testid="category-button"]').click();

    cy.get('[data-testid="category-item-0"]').should('be.visible');

    cy.get('[data-testid="category-item-0"]').click();

    cy.get('[data-testid="category-button"]').should('contain.text', 'Rock');

    cy.get('[data-testid="category-button"]').should('have.text', 'Rock').click();

    cy.get('[data-testid="category-button"]').should('contain.text', 'Rock');
  });

  it('should toggle category selection on click', () => {
    cy.get('[data-testid="category-button"]').click();

    cy.get('[data-testid="category-item-0"]').click();

    cy.get('[data-testid="category-item-0"]').find('.opacity-100').should('exist');

    cy.get('[data-testid="category-item-0"]').click();

    cy.get('[data-testid="category-item-0"]').find('.opacity-0').should('exist');
  });
});
