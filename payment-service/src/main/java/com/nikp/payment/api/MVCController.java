package com.nikp.payment.api;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.nikp.captcha.CaptchaService;
import com.nikp.eventbus.api.EventBus;
import com.nikp.eventbus.domain.Event;
import com.nikp.payment.domain.Payment;
import com.nikp.payment.domain.PaymentDto;
import com.nikp.payment.infrastructure.exceptions.BankValidationException;
import com.nikp.payment.infrastructure.exceptions.ReCaptchaInvalidException;
import com.nikp.payment.infrastructure.exceptions.ReCaptchaUnavailableException;
import com.nikp.payment.infrastructure.persistance.PaymentRepository;

import javax.annotation.PostConstruct;
import javax.ws.rs.ForbiddenException;

@Controller
public class MVCController {

  @Autowired
  private PaymentRepository paymentRepository;
  
  @Autowired
  private CaptchaService captchaService;

  
  @Value("${harness.build}" )
  String buildNumber;
  @Value("${harness.se}" )
  String seName;

  

  @PostConstruct
  private void init() {
    paymentRepository.save(new Payment("T1", "Current Account", "Savings Account", 100L));
  }

  @Autowired
  private EventBus eventBus;

  @RequestMapping("/")
  public String indexView(@RequestParam(name = "number", required = false, defaultValue = "") 
  String number, @RequestParam(name = "sename", required = false, defaultValue = "") 
  String sename, Model model) {
    System.out.println("all payments executed");
    model.addAttribute("list", paymentRepository.findAll());
    model.addAttribute("number",buildNumber );
    model.addAttribute("sename", seName);
    return "allPayments";
  }

  
  @PostMapping("/mvc/payment")
  public String paymentSubmit(@ModelAttribute PaymentDto paymentDto,@RequestParam(value="g-recaptcha-response") String response,@RequestParam(name = "number", required = false, defaultValue = "") 
  String number, @RequestParam(name = "sename", required = false, defaultValue = "") 
  String sename, Model model) {


  if(paymentDto.getBankValidation().isEmpty())
  {
	try { 
		captchaService.processResponse(response);
	}catch(BankValidationException e) {
		
		model.addAttribute(paymentDto);
		model.addAttribute("response",response);
		
		return "bankError";
	}catch(ReCaptchaInvalidException re)
	{
		return "captchaError";
	}catch(ReCaptchaUnavailableException reU) {
		return "captchaError";
	}
  }
    paymentRepository.save(new Payment(paymentDto.getUserId(), paymentDto.getAccountFrom(), paymentDto.getAccountTo(), paymentDto.getAmount()));
    eventBus.publish(new Event("SAVE", "Save payment" + paymentDto));
    model.addAttribute("list", paymentRepository.findAll());
    model.addAttribute("number",buildNumber );
    model.addAttribute("sename", seName);
    
   
    return "allPayments";
  }

  @GetMapping("/mvc/createPayment")
  public String paymentForm( @ModelAttribute PaymentDto paymentDto,@RequestParam(name = "number", required = false, defaultValue = "") 
  String number, @RequestParam(name = "sename", required = false, defaultValue = "") 
  String sename, Model model) {

    model.addAttribute("paymentDto", new PaymentDto());
    model.addAttribute("number",buildNumber );
    model.addAttribute("sename", seName);

  
    return "create";

    
  }
  
  @PostMapping("/mvc/payment/bank")
  public String paymentSubmitBank(@ModelAttribute PaymentDto paymentDto,@RequestParam(name = "number", required = false, defaultValue = "") 
  String number, @RequestParam(name = "sename", required = false, defaultValue = "") 
  String sename, Model model) {


	
    paymentRepository.save(new Payment(paymentDto.getUserId(), paymentDto.getAccountFrom(), paymentDto.getAccountTo(), paymentDto.getAmount()));
    eventBus.publish(new Event("SAVE", "Save payment" + paymentDto));
    model.addAttribute("list", paymentRepository.findAll());
    model.addAttribute("number",buildNumber );
    model.addAttribute("sename", seName);
    
   
    return "allPayments";

  
  }
  
}
