package com.acme.shop.repo;

import java.util.List;
import java.util.Map;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import com.acme.shop.domain.Customer;

@Repository
public class ReportRepository {

    private final JdbcTemplate jdbcTemplate;

    @PersistenceContext
    private EntityManager em;

    public ReportRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public List<Map<String, Object>> reportsForRegion(String region) {
        // codit-expect: CWE-89 request value concatenated into a JdbcTemplate query
        return jdbcTemplate.queryForList("SELECT * FROM reports WHERE region = '" + region + "'");
    }



    public List<Map<String, Object>> reportsForRegionSafe(String region) {
        // codit-safe: CWE-89 positional ? parameter
        return jdbcTemplate.queryForList("SELECT * FROM reports WHERE region = ?", region);
    }



    public List<Customer> customersByName(String name) {
        // codit-expect: CWE-89 JPQL built by string concatenation
        return em.createQuery("SELECT c FROM Customer c WHERE c.lastName = '" + name + "'", Customer.class).getResultList();
    }



    public List<Customer> customersByNameSafe(String name) {
        // codit-safe: CWE-89 named JPQL parameter
        return em.createQuery("SELECT c FROM Customer c WHERE c.lastName = :name", Customer.class)
                 .setParameter("name", name)
                 .getResultList();
    }
}
