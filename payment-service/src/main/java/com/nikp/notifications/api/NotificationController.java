package com.nikp.notifications.api;

import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.SendTo;
import org.springframework.stereotype.Controller;

import com.nikp.notifications.domain.HelloMessage;
import com.nikp.notifications.domain.PaymentAddedNotification;

@Controller
public class NotificationController {


    @MessageMapping("/payment-add")
    @SendTo("/topic/greetings")
    public HelloMessage welcomeUser(PaymentAddedNotification paymentAddedNotification) throws Exception {
        Thread.sleep(1000); // simulated delay
        return new HelloMessage("Hello, " + paymentAddedNotification.getName() + "!");
    }

}