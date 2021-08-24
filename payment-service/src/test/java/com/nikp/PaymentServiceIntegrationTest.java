package com.nikp;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import com.nikp.payment.api.PaymentService;
import com.nikp.payment.domain.Payment;

@RunWith(SpringRunner.class)
@SpringBootTest
public class PaymentServiceIntegrationTest {

    @Autowired
    PaymentService paymentService;

    @Test
    public void shouldMakeAPayment() {
        paymentService.pay(new Payment("user_me", "A1", "TO1", 410L));
    }

}
