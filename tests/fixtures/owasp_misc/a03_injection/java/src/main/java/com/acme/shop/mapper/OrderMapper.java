package com.acme.shop.mapper;

import java.util.List;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import com.acme.shop.domain.Order;

@Mapper
public interface OrderMapper {

    List<Order> findByCustomer(@Param("customerId") long customerId, @Param("sortColumn") String sortColumn);

    List<Order> searchByKeyword(@Param("keyword") String keyword);

    List<Order> searchByKeywordSafe(@Param("keyword") String keyword);



    // codit-expect: CWE-89 ${status} placeholder concatenates the request value into the SQL
    @Select("SELECT id, customer_id, status, total FROM orders WHERE status = '${status}'")
    List<Order> findByStatus(@Param("status") String status);



    // codit-safe: CWE-89 #{id} is a bound parameter
    @Select("SELECT id, customer_id, status, total FROM orders WHERE id = #{id}")
    Order findById(@Param("id") long id);
}
