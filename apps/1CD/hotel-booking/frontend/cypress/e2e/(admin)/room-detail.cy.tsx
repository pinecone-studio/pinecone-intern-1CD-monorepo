describe('Room detail page in admin folder', () => {
  const mockRoomDetail = {
    getRoom: {
      hotelId: '',
      roomType: 'Economy Single Room',
      roomCount: 2,
      roomNumber: 1,
      roomService: {
        bathroom: ['eee', 'eee', 'aaa'],
        accessability: ['rrr', 'ddd', 'eedd'],
        entertaiment: ['eee', 'eee', 'aaa'],
        foodDrink: ['rrr', 'ddd', 'eedd'],
      },
    },
  };

  beforeEach(() => {
    cy.intercept('POST', '/api/graphql', (req) => {
      if (req.body.operationName === 'GetRoom') {
        req.reply({ data: mockRoomDetail });
      }
    }).as('getRoom');

    cy.visit('/room-detail/67734f9cc1bc07a554f731a0');
  });

  it('1.Should render room-detail', () => {
    cy.get('[data-cy=Room-Detail-Page]').should('exist').and('be.visible');
  });

  it('2.GeneralInfo Dialog should be visible when edit button is clicked', () => {
    cy.get('[data-cy=General-Info-Dialog-Button]').should('exist').click();
    cy.get('[data-cy=General-Info-Fields-Dialog]').should('exist');
    cy.get('[data-cy=General-Info-Cancel-Button]').should('exist').click();
    cy.get('[data-cy=General-Info-Fields-Dialog]').should('not.be.visible');
  });

  it('3.RoomServices-Dialog should be visible when edit button is clicked', () => {
    cy.get('[data-cy=Room-Service-Dialog-Button]').should('exist').click();
    cy.get('[data-cy=Room-Services-Dialog]').should('exist');
    cy.get('[data-cy=Room-Services-Cancel-Button]').click();
    cy.get('[data-cy=Room-Services-Dialog]').should('not.be.visible');
  });

  it('4.ImagesDialog should be visible when edit button is clicked', () => {
    cy.get('[data-cy=Images-Dialog-Button]').should('exist').click();
    cy.get('[data-cy=Images-Dialog]').should('exist');
    cy.get('[data-cy=Images-Cancel-Button]').should('exist').click();
    cy.get('[data-cy=Images-Dialog]').should('not.be.visible');
  });
});
