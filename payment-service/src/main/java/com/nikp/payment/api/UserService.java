package com.nikp.payment.api;

import java.util.List;
import java.util.Optional;

import com.nikp.payment.domain.PaymentAndUser;
import com.nikp.payment.domain.User;


public interface UserService {
  List<User> getAllUsers();
  void insert(User user);
  Optional<PaymentAndUser> getPaymentAndUsersForUserId(String userId);
}
