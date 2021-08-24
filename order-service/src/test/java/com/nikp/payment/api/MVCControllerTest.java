package com.nikp.payment.api;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.nikp.PaymentApplication;
import com.nikp.captcha.CaptchaService;
import com.nikp.eventbus.api.EventBus;
import com.nikp.payment.api.MVCController;
import com.nikp.payment.domain.Payment;
import com.nikp.payment.domain.PaymentDto;
import com.nikp.payment.infrastructure.persistance.PaymentRepository;
import com.nikp.payment.infrastructure.security.SpringSecurityWebAppConfig;




import java.util.Arrays;

import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.core.IsNull.nullValue;
import static org.hamcrest.core.StringContains.containsString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@RunWith(SpringRunner.class)
@AutoConfigureMockMvc
@ContextConfiguration(classes = {PaymentApplication.class, SpringSecurityWebAppConfig.class})
@WebMvcTest(
    controllers = MVCController.class
)
public class MVCControllerTest {

  @MockBean
  private PaymentRepository paymentRepository;
  
  @MockBean
  private CaptchaService captchaService;

  @MockBean
  private EventBus eventBus;

  @Autowired
  private MockMvc mockMvc;

  @Test
  public void shouldReturnAllPayments() throws Exception {
    //given
    Iterable<Payment> payments = Arrays.asList(
        new Payment("u1", "from1",
            "to1", 23L));
    when(paymentRepository.findAll()).thenReturn(payments);

    //when, then
    this.mockMvc.perform(get("/")).andDo(print())
        .andExpect(status().isOk())
        .andExpect(content().string(containsString("from1")))
        .andExpect(content().string(containsString("to1")))
        .andReturn();
  }

  @Test
  public void shouldReturnFormForCreatingPayment() throws Exception {
    //when, then
    this.mockMvc.perform(get("/mvc/createPayment")).andDo(print())
        .andExpect(status().isOk())
        .andExpect(content().string(containsString(
            "<form")))
        .andReturn();
  }

  @Test
  public void shouldPostNewPayment() throws Exception {
    //given
    PaymentDto paymentDto = new PaymentDto();
    paymentDto.setUserId("u_id1");
    paymentDto.setAccountFrom("51351");
    paymentDto.setAccountTo("123");
 

    mockMvc.perform(
        post("/mvc/payment")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .sessionAttr("paymentDto", paymentDto)
    )
        .andExpect(status().is4xxClientError());

  }
}