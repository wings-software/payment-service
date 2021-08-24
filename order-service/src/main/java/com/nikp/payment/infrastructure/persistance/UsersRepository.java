package com.nikp.payment.infrastructure.persistance;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;

import com.nikp.payment.domain.User;

import java.util.List;

public interface UsersRepository extends CrudRepository<User, Long> {

  @Query("select t from User t where t.name =:name")
  List<User> findByName(@Param("name") String name);
}
