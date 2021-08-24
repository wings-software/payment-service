package com.nikp.payment.details.api;

import com.nikp.mock.PaymentDetailsMock;
import com.nikp.payment.details.api.PaymentDetailsController;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

import static org.assertj.core.api.Java6Assertions.assertThat;


@RunWith(SpringRunner.class)
@SpringBootTest
@ActiveProfiles("integration")
public class PaymentDetailsControllerTest {

  @Autowired
  private PaymentDetailsMock paymentDetailsMock;

  @Autowired
  private PaymentDetailsController paymentDetailsController;

  @Test
  public void test() throws Exception {
    //given
    paymentDetailsMock.addInfo("SUPER_CITY", "Beautiful Town");

    //when
    String res = paymentDetailsController.getInfoAboutPayment("SUPER_CITY");

    //then
    assertThat(res).isEqualTo("Beautiful Town");

  }

}