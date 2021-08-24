package com.nikp.measurments;

import org.assertj.core.api.Assertions;
import org.junit.Test;
import org.springframework.metrics.instrument.Counter;
import org.springframework.metrics.instrument.MeterRegistry;
import org.springframework.metrics.instrument.simple.SimpleMeterRegistry;

public class CounterTest {
  @Test
  public void shouldUseCounter() {
    //given
    MeterRegistry metricRegistry = new SimpleMeterRegistry();
    Counter counter = metricRegistry
        .counter("indicates instance count of the object");

    //when
    actionInvocationMeasurement(counter);

    //then
    Assertions.assertThat(counter.count()).isEqualTo(100);

  }

  public void actionInvocationMeasurement(Counter counter) {
    for (int i = 0; i < 100; i++) {
      counter.increment();
    }
  }
}
