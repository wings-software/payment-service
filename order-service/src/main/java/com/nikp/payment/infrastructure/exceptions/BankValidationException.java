package com.nikp.payment.infrastructure.exceptions;

public class BankValidationException extends RuntimeException {

    private static final long serialVersionUID = 5861310537366287163L;

    public BankValidationException() {
        super();
    }

    public BankValidationException(final String message, final Throwable cause) {
        super(message, cause);
    }

    public BankValidationException(final String message) {
        super(message);
    }

    public BankValidationException(final Throwable cause) {
        super(cause);
    }

}
