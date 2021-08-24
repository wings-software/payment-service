package com.nikp.repository;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import com.nikp.payment.domain.Payment;
import com.nikp.payment.infrastructure.persistance.PaymentRepository;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;


@RunWith(SpringRunner.class)
@SpringBootTest
public class PaymentRepositoryIntegrationTest {

    @Autowired
    PaymentRepository paymentRepository;

    @Test
    public void shouldSavePaymentAndRetrieveItByUserId() {
        //given
        String userId = "joseph";
        Payment payment = new Payment(userId, "124215", "t5356315", 23L);

        //when
        paymentRepository.save(payment);
        List<Payment> payments = paymentRepository.findByUserId(userId);

        //then
        assertThat(payments.get(0).getAccountFrom()).isEqualTo("124215");
        assertThat(payments.get(0).getAccountTo()).isEqualTo("t5356315");
        
    }
    

    @Test
    public void shouldRetrieveAllPaymentsThatHave123AsAccountFrom() {
        //given
        List<Payment> payments = Arrays.asList(
                new Payment(UUID.randomUUID().toString(), "123", "55555", 23L),
                new Payment(UUID.randomUUID().toString(), "123", "77777", 23L),
                new Payment(UUID.randomUUID().toString(), "77777", "2145", 23L)
        );

        //when
        paymentRepository.saveAll(payments);
        List<Payment> foundPayments = paymentRepository.findByFromAccount("123");

        //then
        assertThat(foundPayments.size()).isEqualTo(2);
    }

}