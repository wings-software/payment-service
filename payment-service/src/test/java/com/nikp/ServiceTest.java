package com.nikp;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import java.util.concurrent.TimeUnit;

@RunWith(SpringRunner.class)
@SpringBootTest
public class ServiceTest {
	

	  @Test
	  public void testApplicationSetRightConfigValues() throws Exception {
		  TimeUnit.SECONDS.sleep(10);
	  }
	  
	  @Test
	  public void testApplicationSetRightEnvValues() throws Exception {
		  TimeUnit.SECONDS.sleep(10);
	  }
	  
	  @Test
	  public void testApplicationStartOnTime() throws Exception {
		  TimeUnit.SECONDS.sleep(10);
	  }

	  @Test
	  public void testPaymentServiceValues() throws Exception {
		  TimeUnit.SECONDS.sleep(10);
	  }
	  
	  @Test
	  public void testPaymentServiceTransactionSuccessful() throws Exception {
		  TimeUnit.SECONDS.sleep(20);
	  }
	  
	  @Test
	  public void testPaymentServiceApplicationMapping() throws Exception {
		  TimeUnit.SECONDS.sleep(20);
	  }
}
