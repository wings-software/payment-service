package com.nikp.captcha.api;

import java.util.Date;
import java.util.List;

import org.springframework.cloud.cloudfoundry.com.fasterxml.jackson.annotation.JsonProperty;

public class CaptchaResponse {

    private Boolean success;
    private Date timestamp;
    private String hostname;
    @JsonProperty("error-codes")
    private List<String> errorCodes;
    
    
    
	public Boolean getSuccess() {
		return success;
	}
	public void setSuccess(Boolean success) {
		this.success = success;
	}
	public Date getTimestamp() {
		return timestamp;
	}
	public void setTimestamp(Date timestamp) {
		this.timestamp = timestamp;
	}
	public String getHostname() {
		return hostname;
	}
	public void setHostname(String hostname) {
		this.hostname = hostname;
	}
	public List<String> getErrorCodes() {
		return errorCodes;
	}
	public void setErrorCodes(List<String> errorCodes) {
		this.errorCodes = errorCodes;
	}

}