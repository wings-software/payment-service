package com.nikp.payment.domain;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

import org.springframework.beans.factory.annotation.Value;

@Entity
public class Payment {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    private String userId;
    private String accountFrom;
    private String accountTo;
    private Long amount;
    


	public Payment() {
    }

    public Payment(String userId, String accountFrom, String accountTo, Long amount) {
        this.userId = userId;
        this.accountFrom = accountFrom;
        this.accountTo = accountTo;
        this.amount = amount;
    }

    public Payment(Long id, String userId, String accountFrom, String accountTo, Long amount) {
        this.id = id;
        this.userId = userId;
        this.accountFrom = accountFrom;
        this.accountTo = accountTo;
        this.amount = amount;
    }

    public String getUserId() {
    	String userId = this.userId;
        return userId;
    }

    public String getAccountFrom() {
        return accountFrom;
    }

    public String getAccountTo() {
        return accountTo;
    }

    public Long getId() {
        return id;
    }

    public Long getAmount() {
        return amount;
    }

    @Override
    public String toString() {
        return "Payment{" +
            "id=" + id +
            ", userId='" + userId + '\'' +
            ", accountFrom='" + accountFrom + '\'' +
            ", accountTo='" + accountTo + '\'' +
            ", amount=" + amount +
            '}';
    }
}
