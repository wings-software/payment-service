package com.nikp.payment.test;

import static org.junit.Assert.assertEquals;

import java.util.concurrent.TimeUnit;

import org.assertj.core.api.Assertions;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

import com.nikp.PaymentApplication;

import com.nikp.payment.infrastructure.security.SpringSecurityWebAppConfig;


public class TiServiceTest {

    
    @MockBean
    private TiService tiService;

    @Before 
    public void setUp() {
    	tiService = new TiService();
    }
    
    @Test
    public void testCalculateInterest() {
        Assertions.assertThat(tiService.calculateInterest(4, 5)).isEqualTo(20);
    }
    
    @Test
    public void testExchangeRateGBPtoUSD() throws InterruptedException {
    //	TimeUnit.SECONDS.sleep(20);
        Assertions.assertThat(tiService.calculateExchangeRate(4, 5)).isEqualTo(20);
    }
    
    @Test
    public void testExchangeRateUSDtoGBP() throws InterruptedException {
    	//TimeUnit.SECONDS.sleep(20);
        Assertions.assertThat(tiService.calculateExchangeRate(4, 5)).isEqualTo(20);
    }
    
    
    @Test
    public void testExchangeRateGBPtoEuro() throws InterruptedException {
    //	TimeUnit.SECONDS.sleep(20);
        Assertions.assertThat(tiService.calculateExchangeRate(4, 5)).isEqualTo(20);
    }
    
    @Test
    public void testExchangeRateJPYtoGBP() throws InterruptedException {
    	//TimeUnit.SECONDS.sleep(20);
        Assertions.assertThat(tiService.calculateExchangeRate(4, 5)).isEqualTo(20);
    }
    
    @Test
    public void testExchangeRateGBPtoJPY() throws InterruptedException {
    	//TimeUnit.SECONDS.sleep(20);
        Assertions.assertThat(tiService.calculateExchangeRate(4, 5)).isEqualTo(20);
    }
    
    @Test
    public void testExchangeRateCHFtoGBP() throws InterruptedException {
    //	TimeUnit.SECONDS.sleep(20);
        Assertions.assertThat(tiService.calculateExchangeRate(4, 5)).isEqualTo(20);
    }
    
    @Test
    public void testExchangeRateGBPtoCHF() throws InterruptedException {
    	//TimeUnit.SECONDS.sleep(20);
        Assertions.assertThat(tiService.calculateExchangeRate(4, 5)).isEqualTo(20);
    }
    
    
    @Test
    public void testExchangeRateAUDtoGBP() throws InterruptedException {
    //	TimeUnit.SECONDS.sleep(20);
        Assertions.assertThat(tiService.calculateExchangeRate(4, 5)).isEqualTo(20);
    }
    
    @Test
    public void testExchangeRateGBPtoAUD() throws InterruptedException {
    	//TimeUnit.SECONDS.sleep(20);
        Assertions.assertThat(tiService.calculateExchangeRate(4, 5)).isEqualTo(20);
    }
    
    

}
