package com.nikp.payment.infrastructure.persistance;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;

import com.nikp.payment.domain.Payment;

import java.util.List;

public interface PaymentRepository extends CrudRepository<Payment, Long> {

    @Query("select t from Payment t where t.userId =:userId")
    List<Payment> findByUserId(@Param("userId") String userId);

    @Query("select t from Payment t where t.accountFrom =:accountFrom")
    List<Payment> findByFromAccount(@Param("accountFrom") String accountFrom);
}
