package com.nikp.eventbus.api;

import com.nikp.eventbus.domain.Event;

public interface EventBus {
  void publish(Event event);
  Event receive();
}
