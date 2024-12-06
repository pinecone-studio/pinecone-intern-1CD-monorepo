describe('register with email page',()=>{
    beforeEach(()=>{
        cy.visit('/register/email');
    });
    it('1.should render register page correctly',()=>{
        cy.get('[data-cy="register-email-header"]').should('be.visible');
        cy.contains('tinder').should('be.visible')
        cy.contains('Create an account').should('be.visible');
        cy.contains('Enter your email below to create your account').should('be.visible');
    })
    it('2.should display the email input field and accept user input',()=>{
        cy.get('[data-cy="register-email-input"]').should('be.visible').and('have.attr','placeholder','name@example.com');
        cy.get('[data-cy="register-email-input"]').type('test@gmail.com').should('have.value','test@gmail.com');
    })
    it('3.should display the continue button and interact with it',()=>{
        cy.get('[data-cy="register-continue-button"]').should('be.visible').and('contain.text', 'Continue');
        cy.get('[data-cy="register-email-input"]').type('test@example.com');
      cy.get('[data-cy="register-continue-button"]').should('be.enabled');
    })
    it('4.should show a toast notification when no email is provided',()=>{
        cy.get('[data-cy="register-email-input"]').type('');
        cy.get('[data-cy="register-continue-button"]').click();
        cy.contains('email is required').should('be.visible');
    })
    it('5.should redirect to otp page ',()=>{
        const mockEmail = 'test@example.com';
        cy.get('[data-cy="register-email-input"]').type(mockEmail);
        cy.get('[data-cy="register-continue-button"]').click();
        cy.contains(`Success! We've sent a verification otp to ${mockEmail}. Please check your inbox.`).should('exist')
        cy.window().then((window) => {
            expect(window.localStorage.getItem('userEmail')).to.equal('cypress1213@gmail.com');
          });
        cy.url().should('include', '/register/otp');
    })
    it('6.should show an error toast when the email aleady exists',()=>{
        cy.get('[data-cy="register-email-input"]').type('satsuraltumurbat@gmail.com');
        cy.get('[data-cy="register-continue-button"]').click();
        cy.contains('email already exist').should('be.visible');
    });
    
    it('7.should show an error toast when the unexpected error occurs',()=>{
        cy.get('[data-cy="register-email-input"]').type('cypress');
        cy.get('[data-cy="register-continue-button"]').click();
        cy.contains('Failed to send OTP email').should('be.visible');
    });
  
})