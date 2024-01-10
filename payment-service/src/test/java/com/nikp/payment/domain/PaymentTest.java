package com.nikp.payment.domain;


import org.junit.Assert;
import org.junit.Test;

public class PaymentTest {
	
	
	 @Test
	 public void testAccesors_shouldAccessUserId() {
		 Payment payment = new Payment("testuser","accountFrom","accountTo",(long) 100);
		 String user=payment.getUserId();
		 Assert.assertEquals("testuser", user);
		 
	 }
	 
	 @Test
	 public void testAccesors_shouldAccessAccountFrom() {
		 Payment payment = new Payment("testuser","accountFrom","accountTo",(long) 100);
		 String accountFrom=payment.getAccountFrom();
		 Assert.assertEquals("accountFrom", accountFrom);
		 
	 }
	 
	 @Test
	 public void testAccesors_shouldAccessAccountTo() {
		 Payment payment = new Payment("testuser","accountFrom","accountTo",(long) 100);
		 String accountTo=payment.getAccountTo();
		 Assert.assertEquals("accountTo", accountTo);
		 
	 }
	 
	 @Test
	 public void testAccesors_shouldAccessAmount() {
		 Payment payment = new Payment("testuser","accountFrom","accountTo",100L);
		 Long amount=payment.getAmount();
		 Assert.assertEquals(Long.valueOf(100L), amount);
		 
	 }
}
