package com.nikp.payment.domain;

import javax.persistence.Transient;

import org.springframework.beans.factory.annotation.Value;

public class PaymentDto {

    private String userId;
    private String accountFrom;
    private String accountTo;
    private Long amount;
    private String captchaResponse;
    private String bankValidation="";
    
    

	public String getBankValidation() {
		return bankValidation;
	}

	public void setBankValidation(String bankValidation) {
		this.bankValidation = bankValidation;
	}

	@Value( "${harness.build}" )
	private String buildNumber;

   public String getBuildNumber() {
		return buildNumber;
	}

	public void setBuildNumber(String buildNumber) {
		this.buildNumber = buildNumber;
	}
	
	@Transient
	private String captcha;
	
	@Transient
	private String hiddenCaptcha;
	
	@Transient
	private String realCaptcha;
    
    public String getCaptcha() {
		return captcha;
	}

	public void setCaptcha(String captcha) {
		this.captcha = captcha;
	}

	public String getHiddenCaptcha() {
		return hiddenCaptcha;
	}

	public void setHiddenCaptcha(String hiddenCaptcha) {
		this.hiddenCaptcha = hiddenCaptcha;
	}

	public String getRealCaptcha() {
		return realCaptcha;
	}

	public void setRealCaptcha(String realCaptcha) {
		this.realCaptcha = realCaptcha;
	}

	public String getCaptchaResponse() {
		return captchaResponse;
	}

	public void setCaptchaResponse(String captchaResponse) {
		this.captchaResponse = captchaResponse;
	}

	public PaymentDto() {
    }

    public PaymentDto(String userId, String accountFrom, String accountTo, Long amount) {
        this.userId = userId;
        this.accountFrom = accountFrom;
        this.accountTo = accountTo;
        this.amount = amount;
    }

    public String getUserId() {
        return userId;
    }

    public String getAccountFrom() {
        return accountFrom;
    }

    public String getAccountTo() {
        return accountTo;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public void setAccountFrom(String accountFrom) {
        this.accountFrom = accountFrom;
    }

    public void setAccountTo(String accountTo) {
        this.accountTo = accountTo;
    }

    public Long getAmount() {
        return amount;
    }

    public void setAmount(Long amount) {
        this.amount = amount;
    }

    @Override
    public String toString() {
        return "PaymentDto{" +
            "userId='" + userId + '\'' +
            ", accountFrom='" + accountFrom + '\'' +
            ", accountTo='" + accountTo + '\'' +
            ", amount=" + amount +
            '}';
    }
}
