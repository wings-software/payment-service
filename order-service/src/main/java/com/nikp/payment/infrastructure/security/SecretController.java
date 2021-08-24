package com.nikp.payment.infrastructure.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.nikp.payment.infrastructure.persistance.PaymentRepository;

@RestController
public class SecretController {

    @Autowired
    private PaymentRepository paymentRepository;

    @RequestMapping("/secret")
    public Long numberOfPayment() {
        return paymentRepository.count();
    }
}
