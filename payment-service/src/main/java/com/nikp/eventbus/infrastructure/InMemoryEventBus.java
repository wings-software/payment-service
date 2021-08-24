package com.nikp.eventbus.infrastructure;

import org.springframework.stereotype.Component;

import com.nikp.eventbus.api.EventBus;
import com.nikp.eventbus.domain.Event;

import java.util.Queue;
import java.util.concurrent.LinkedBlockingDeque;

@Component
public class InMemoryEventBus implements EventBus {
  private final Queue<Event> queue = new LinkedBlockingDeque<>();

  @Override
  public void publish(Event event) {
    queue.add(event);
  }

  @Override
  public Event receive() {
    return queue.poll();
  }
}
