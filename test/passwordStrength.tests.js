const expect = require('chai').expect;
const passwordStrength = require('../admin/passwordStrength');

describe('passwordStrength', () => {
  describe('validate', () => {
    describe('given password is missing or empty', () => {
      it('should return falsy for null', () => {
        expect(passwordStrength.validate(null)).to.not.be.ok;
      });

      it('should return falsy for undefined', () => {
        expect(passwordStrength.validate(undefined)).to.not.be.ok;
      });

      it('should return falsy for empty string', () => {
        expect(passwordStrength.validate('')).to.not.be.ok;
      });
    });

    describe('given password is too short', () => {
      it('should return falsy for a 1-character password', () => {
        expect(passwordStrength.validate('a')).to.not.be.ok;
      });

      it('should return falsy for a 14-character password (one below minimum)', () => {
        expect(passwordStrength.validate('a'.repeat(14))).to.not.be.ok;
      });
    });

    describe('given password meets the length requirement', () => {
      it('should return truthy for a 15-character password (minimum)', () => {
        expect(passwordStrength.validate('a'.repeat(15))).to.be.ok;
      });

      it('should return truthy for a 40-character password', () => {
        expect(passwordStrength.validate('a'.repeat(40))).to.be.ok;
      });

      it('should return truthy for a 64-character password (maximum)', () => {
        expect(passwordStrength.validate('a'.repeat(64))).to.be.ok;
      });
    });

    describe('given password is too long', () => {
      it('should return falsy for a 65-character password (one above maximum)', () => {
        expect(passwordStrength.validate('a'.repeat(65))).to.not.be.ok;
      });

      it('should return falsy for a very long password', () => {
        expect(passwordStrength.validate('a'.repeat(200))).to.not.be.ok;
      });
    });
  });

  describe('validateToString', () => {
    describe('given password is missing or empty', () => {
      it('should return required message for null', () => {
        expect(passwordStrength.validateToString(null)).to.equal('Password is required.');
      });

      it('should return required message for undefined', () => {
        expect(passwordStrength.validateToString(undefined)).to.equal('Password is required.');
      });

      it('should return required message for empty string', () => {
        expect(passwordStrength.validateToString('')).to.equal('Password is required.');
      });
    });

    describe('given password is too short', () => {
      it('should return minimum length message for a 14-character password', () => {
        expect(passwordStrength.validateToString('a'.repeat(14))).to.equal(
          'Password must be at least 15 characters long.'
        );
      });

      it('should return minimum length message for a 1-character password', () => {
        expect(passwordStrength.validateToString('a')).to.equal(
          'Password must be at least 15 characters long.'
        );
      });
    });

    describe('given password meets the length requirement', () => {
      it('should return empty string for a 15-character password (minimum)', () => {
        expect(passwordStrength.validateToString('a'.repeat(15))).to.equal('');
      });

      it('should return empty string for a 40-character password', () => {
        expect(passwordStrength.validateToString('a'.repeat(40))).to.equal('');
      });

      it('should return empty string for a 64-character password (maximum)', () => {
        expect(passwordStrength.validateToString('a'.repeat(64))).to.equal('');
      });
    });

    describe('given password is too long', () => {
      it('should return maximum length message for a 65-character password', () => {
        expect(passwordStrength.validateToString('a'.repeat(65))).to.equal(
          'Password must be no more than 64 characters long.'
        );
      });

      it('should return maximum length message for a very long password', () => {
        expect(passwordStrength.validateToString('a'.repeat(200))).to.equal(
          'Password must be no more than 64 characters long.'
        );
      });
    });
  });
});