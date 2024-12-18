describe('Birthday Form Navigation', () => {
  beforeEach(() => {
    cy.visit('/register/birthday');
  });

  it('1. should display the logo and header', () => {
    cy.get('[data-cy="logo-container"]').should('be.visible');
    cy.contains('tinder').should('be.visible');
    cy.contains('How old are you?').should('be.visible');
    cy.contains('Please enter your age to continue').should('be.visible');
  });

  it('2. should allow entering December 1st, 2024, and submit the form', () => {
    cy.get('[data-cy="day-input"]').type('01');
    cy.get('[data-cy="month-input"]').type('12');
    cy.get('[data-cy="year-input"]').type('2024');

    cy.get('[data-cy="day-input"]').should('have.value', '01');
    cy.get('[data-cy="month-input"]').should('have.value', '12');
    cy.get('[data-cy="year-input"]').should('have.value', '2024');

    cy.get('[data-cy="next-button"]').click();

    cy.url().should('include', '/');
  });

  it('3. should show an error if the user is under 18 years old', () => {
    cy.get('[data-cy="day-input"]').type('01');
    cy.get('[data-cy="month-input"]').type('12');
    cy.get('[data-cy="year-input"]').type('2010');

    cy.get('[data-cy="day-input"]').should('have.value', '01');
    cy.get('[data-cy="month-input"]').should('have.value', '12');
    cy.get('[data-cy="year-input"]').should('have.value', '2010');

    cy.get('[data-cy="next-button"]').click();

    cy.contains("We'll meet when you turn 18.").should('be.visible');
  });

  it('4. should show an error message if no date is entered and "Next" is clicked', () => {
    cy.get('[data-cy="next-button"]').click();

    cy.contains('Please complete the date of birth').should('be.visible');
  });

  it('5. should show an error message if an invalid date is entered', () => {
    cy.get('[data-cy="day-input"]').type('32');
    cy.get('[data-cy="month-input"]').type('13');
    cy.get('[data-cy="year-input"]').type('2024');

    cy.get('[data-cy="next-button"]').click();

    cy.contains('Please enter a valid date').should('be.visible');
  });

  it('6. should go back to the home page when clicking "Back"', () => {
    cy.get('[data-cy="back-button"]').click();

    cy.url().should('include', '/');
  });
});
