package com.nikp.payment.test;

import org.springframework.stereotype.Service;

@Service("tiService")
public class TiService {
    
	public int calculateInterest(int a, int b) {
        return a * b;
    }
	
	public int calculateExchangeRate(int a, int b) {
		return a * b;
	}

}
