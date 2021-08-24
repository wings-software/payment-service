package com.nikp.mock;


import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import com.nikp.payment.details.api.PaymentDetails;

import java.util.LinkedHashMap;
import java.util.Map;

@Component
@Profile("integration")
public class PaymentDetailsMock implements PaymentDetails {
  private final Map<String, String> info = new LinkedHashMap<>();

  public void addInfo(String key, String value){
    info.put(key, value);
  }

  @Override
  public String getInfoAboutPayment(String cityName) {
    return info.get(cityName);
  }
}
