package com.nikp.payment.api;

import com.nikp.payment.domain.Payment;

public interface PaymentService {
    boolean pay(Payment payment);
}
