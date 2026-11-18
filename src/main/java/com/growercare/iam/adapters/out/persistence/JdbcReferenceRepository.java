package com.growercare.iam.adapters.out.persistence;

import com.growercare.common.sql.NamedSqlRegistry;
import com.growercare.iam.application.port.ReferenceRepository;
import java.util.List;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** {@link ReferenceRepository} with named SQL from {@code sql/postgres/reference.sql}. */
@Repository
class JdbcReferenceRepository implements ReferenceRepository {

    private final JdbcClient jdbc;
    private final NamedSqlRegistry sql;

    JdbcReferenceRepository(JdbcClient jdbc, NamedSqlRegistry sql) {
        this.jdbc = jdbc;
        this.sql = sql;
    }

    @Override
    public boolean countryExists(String country) {
        return jdbc.sql(sql.get("reference.countryExists")).param("country", country).query(Long.class).single() > 0;
    }

    @Override
    public List<Territory> territories(String country) {
        return jdbc.sql(sql.get("reference.territories")).param("country", country)
                .query((rs, i) -> new Territory(rs.getLong("territory_id"), rs.getObject("parent_territory_id", Long.class),
                        rs.getString("territory_code"), rs.getString("name"), rs.getString("territory_level")))
                .list();
    }

    @Override
    public List<GrantableRole> rolesUpTo(int level) {
        return jdbc.sql(sql.get("reference.rolesUpTo")).param("level", level)
                .query((rs, i) -> new GrantableRole(rs.getString("role_code"), rs.getString("name"), rs.getString("scope_kind"),
                        rs.getString("allowed_user_type")))
                .list();
    }

    @Override
    public List<AssignableRow> assignable(long territoryId, String country, String buCode) {
        return jdbc.sql(sql.get("reference.assignable"))
                .param("territoryId", territoryId).param("country", country).param("buCode", buCode)
                .query((rs, i) -> new AssignableRow(rs.getLong("user_id"), rs.getString("display_name"), rs.getString("role_code")))
                .list();
    }
}
