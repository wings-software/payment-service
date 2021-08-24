package com.nikp.payment.infrastructure.persistance;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.nikp.payment.domain.Payment;
import com.nikp.payment.domain.PaymentDto;

import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.List;
import java.util.stream.Collectors;

@Component
public class ReactivePaymentRepository {

    private final PaymentRepository paymentRepository;

    @Autowired
    public ReactivePaymentRepository(PaymentRepository paymentRepository) {

        this.paymentRepository = paymentRepository;
    }

    public Mono<List<PaymentDto>> getPayments(String userId) {
        return Mono.defer(() -> Mono.just(paymentRepository.findByUserId(userId)))
                .subscribeOn(Schedulers.elastic())
                .map(p ->
                        p.stream().map(p1 -> new PaymentDto(p1.getUserId(), p1.getAccountFrom(), p1.getAccountTo(), p1.getAmount()))
                                .collect(Collectors.toList()));
    }

    public Mono<PaymentDto> addPayments(final PaymentDto payment) {
        return Mono.just(payment)
                .map(t -> new Payment(t.getUserId(), t.getAccountFrom(), t.getAccountTo(), t.getAmount()))
                .publishOn(Schedulers.parallel())
                .doOnNext(paymentRepository::save)
                .map(t -> new PaymentDto(t.getUserId(), t.getAccountFrom(), t.getAccountTo(), t.getAmount()));
    }
}
