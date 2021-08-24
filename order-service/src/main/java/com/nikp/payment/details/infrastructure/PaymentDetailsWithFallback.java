package com.nikp.payment.details.infrastructure;

import com.netflix.hystrix.contrib.javanica.annotation.HystrixCommand;
import com.nikp.eventbus.api.EventBus;
import com.nikp.eventbus.domain.Event;
import com.nikp.payment.details.api.PaymentDetails;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.metrics.instrument.MeterRegistry;
import org.springframework.metrics.instrument.Timer;
import org.springframework.metrics.instrument.stats.quantile.GKQuantiles;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.time.Instant;

@Component
@Profile("!integration")
public class PaymentDetailsWithFallback implements PaymentDetails {
  static Logger log = Logger.getLogger(PaymentDetailsWithFallback.class.getName());

  private EventBus eventBus;

  @Autowired
  private MeterRegistry meterRegistry;

  @Autowired
  public PaymentDetailsWithFallback(
      RestTemplate rest,
      EventBus eventBus) {
    this.eventBus = eventBus;
  }

  @HystrixCommand(fallbackMethod = "reliable")
  @Override
  public String getInfoAboutPayment(String account) {
    return request(account);
  }

  public String request(String account) {
    Timer timer = meterRegistry
        .timerBuilder("payment_detail_request")
        .quantiles(GKQuantiles.quantiles(0.99, 0.90, 0.50).create()).create();
    return timer.record(() -> requestForPaymentDetails(account));
  }

  private String requestForPaymentDetails(String account) {

    return "{\"name\" : " + account + ", \"time\": " + Instant.now() + "}";
  }

  public String reliable(String account) {
    meterRegistry.counter("hystrix_fallback").increment();
    return "Info about payment: " + account + " is not currently not available";
  }

  @Scheduled(fixedRate = 1000)
  public void processEvents() {
    Event event = eventBus.receive();
    if (event != null) {
      log.info("received event to process :" + event);
    }

  }
}
