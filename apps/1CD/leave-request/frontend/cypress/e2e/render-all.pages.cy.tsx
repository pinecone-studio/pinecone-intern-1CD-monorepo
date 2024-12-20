import allPages from '../utils/all-pages.json';

describe('render all pages', () => {
  const token = Cypress.env().env['ANNUAL_TOKEN'] as string
    cy.setCookie(
      'authtoken',
      token
    );
  it(`Should render all page`, () => {
    cy.log(JSON.stringify(allPages));
    allPages.forEach((page) => {
      cy.visit(page);
    });
  });
});
