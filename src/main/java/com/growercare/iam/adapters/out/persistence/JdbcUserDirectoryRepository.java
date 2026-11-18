package com.growercare.iam.adapters.out.persistence;

import com.growercare.common.sql.NamedSqlRegistry;
import com.growercare.iam.application.port.UserDirectoryRepository;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** {@link UserDirectoryRepository} with named SQL from {@code sql/postgres/directory.sql}. */
@Repository
class JdbcUserDirectoryRepository implements UserDirectoryRepository {

    /** {@code IN ()} is not valid SQL; a code no country can have keeps an empty set meaning "none". */
    private static final List<String> NONE = List.of("--");

    private static final RowMapper<DirectoryUser> USER = (rs, n) -> new DirectoryUser(
            rs.getLong("user_id"), rs.getString("user_type"), rs.getString("home_country_code"),
            rs.getObject("partner_org_id", Long.class), rs.getString("display_name"), rs.getString("phone_last4"),
            rs.getString("status"));

    private final JdbcClient jdbc;
    private final NamedSqlRegistry sql;

    JdbcUserDirectoryRepository(JdbcClient jdbc, NamedSqlRegistry sql) {
        this.jdbc = jdbc;
        this.sql = sql;
    }

    @Override
    public List<DirectoryUser> search(Search s) {
        String prefix = s.namePrefix() == null ? null : escape(s.namePrefix()) + "%";
        return jdbc.sql(sql.get("directory.search"))
                .param("allCountries", s.allCountries())
                .param("countries", orNone(s.countries()))
                .param("allFullCountries", s.allFullCountries())
                .param("fullCountries", orNone(s.fullCountries()))
                .param("country", s.country())
                .param("userType", s.userType())
                .param("status", s.status())
                .param("prefix", prefix)
                .param("wordPrefix", prefix == null ? null : "% " + prefix)
                .param("qUserId", s.qUserId())
                .param("afterUserId", s.afterUserId())
                .param("limit", s.limit())
                .query(USER)
                .list();
    }

    @Override
    public Optional<DirectoryUser> user(long userId) {
        return jdbc.sql(sql.get("directory.user")).param("userId", userId).query(USER).optional();
    }

    @Override
    public List<StaffName> staffNames(java.util.Collection<Long> ids) {
        if (ids.isEmpty()) {
            return List.of();
        }
        return jdbc.sql(sql.get("directory.staffNames")).param("ids", List.copyOf(ids))
                .query((rs, i) -> new StaffName(rs.getLong("user_id"), rs.getString("display_name"), rs.getString("home_country_code")))
                .list();
    }

    @Override
    public Optional<Contact> contact(long userId) {
        return jdbc.sql(sql.get("directory.contact")).param("userId", userId)
                .query((rs, i) -> new Contact(rs.getLong("user_id"), rs.getString("user_type"), rs.getString("status"),
                        rs.getString("email"), rs.getString("display_name")))
                .optional();
    }

    private static List<String> orNone(Set<String> values) {
        return values.isEmpty() ? NONE : List.copyOf(values);
    }

    /** LIKE metacharacters in user input are literal. */
    static String escape(String text) {
        return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_");
    }
}
