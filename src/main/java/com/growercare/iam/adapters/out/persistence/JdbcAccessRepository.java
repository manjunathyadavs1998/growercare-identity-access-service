package com.growercare.iam.adapters.out.persistence;

import com.growercare.common.sql.NamedSqlRegistry;
import com.growercare.iam.application.port.AccessRepository;
import com.growercare.iam.domain.GeoScopeRequest;
import com.growercare.iam.domain.RoleDefinition;
import com.growercare.iam.domain.StoredGrant;
import com.growercare.iam.domain.UserAccount;
import com.growercare.security.EffectiveGrant;
import com.growercare.security.PiiClearance;
import com.growercare.security.ScopeKind;
import com.growercare.security.UserType;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** {@link AccessRepository} over {@code gc_iam.iam} with named SQL from {@code sql/postgres/{principal,grant}.sql}. */
@Repository
class JdbcAccessRepository implements AccessRepository {

    private final JdbcClient jdbc;
    private final NamedSqlRegistry sql;

    JdbcAccessRepository(JdbcClient jdbc, NamedSqlRegistry sql) {
        this.jdbc = jdbc;
        this.sql = sql;
    }

    private static final RowMapper<UserAccount> USER = (rs, n) -> new UserAccount(
            rs.getLong("user_id"),
            rs.getObject("external_subject", UUID.class),
            UserType.valueOf(rs.getString("user_type")),
            rs.getString("home_country_code"),
            rs.getObject("partner_org_id", Long.class),
            rs.getString("status"));

    @Override
    public Optional<UserAccount> findUserBySubject(UUID subject) {
        return jdbc.sql(sql.get("principal.userBySubject")).param("subject", subject).query(USER).optional();
    }

    @Override
    public Optional<UserAccount> findUser(long userId) {
        return jdbc.sql(sql.get("grant.findUser")).param("userId", userId).query(USER).optional();
    }

    @Override
    public Optional<RoleDefinition> findRole(String roleCode) {
        return jdbc.sql(sql.get("grant.findRole")).param("roleCode", roleCode)
                .query((rs, n) -> new RoleDefinition(
                        rs.getString("role_code"),
                        rs.getInt("role_level"),
                        ScopeKind.valueOf(rs.getString("scope_kind")),
                        UserType.valueOf(rs.getString("allowed_user_type")),
                        rs.getBoolean("privileged")))
                .optional();
    }

    @Override
    public List<EffectiveGrant> effectiveGrants(long userId) {
        record Row(long grantId, String role, int level, ScopeKind kind, PiiClearance pii, Instant validTo) { }
        var rows = jdbc.sql(sql.get("principal.activeGrantsByUser")).param("userId", userId)
                .query((rs, n) -> new Row(rs.getLong("grant_id"), rs.getString("role_code"), rs.getInt("role_level"),
                        ScopeKind.valueOf(rs.getString("scope_kind")), PiiClearance.valueOf(rs.getString("pii_clearance")),
                        instant(rs, "valid_to")))
                .list();
        if (rows.isEmpty()) {
            return List.of();
        }
        var ids = rows.stream().map(Row::grantId).toList();
        Map<Long, Set<String>> permissions = grouped("principal.permissionsByGrants", ids, rs -> rs.getString("permission_code"));
        Map<Long, Set<String>> countries = grouped("principal.countriesByGrants", ids, rs -> rs.getString("country_code"));
        Map<Long, Set<Long>> territories = grouped("principal.territoriesByGrants", ids, rs -> rs.getLong("territory_id"));
        Map<Long, Set<String>> bus = grouped("principal.businessUnitsByGrants", ids, rs -> rs.getString("bu_code"));
        return rows.stream()
                .map(r -> new EffectiveGrant(r.grantId(), r.role(), r.level(), r.kind(), r.pii(),
                        permissions.getOrDefault(r.grantId(), Set.of()),
                        countries.getOrDefault(r.grantId(), Set.of()),
                        territories.getOrDefault(r.grantId(), Set.of()),
                        bus.getOrDefault(r.grantId(), Set.of()),
                        r.validTo()))
                .toList();
    }

    @Override
    public Set<String> activeRoleCodes(long userId) {
        return Set.copyOf(jdbc.sql(sql.get("grant.activeRoleCodesOfUser")).param("userId", userId).query(String.class).list());
    }

    @Override
    public Set<String> sodConflictsOf(String roleCode) {
        return Set.copyOf(jdbc.sql(sql.get("grant.sodConflictsOf")).param("roleCode", roleCode).query(String.class).list());
    }

    @Override
    public Map<Long, String> territoryCountries(Set<Long> territoryIds) {
        return jdbc.sql(sql.get("grant.territoryCountries")).param("territoryIds", List.copyOf(territoryIds))
                .query((rs, n) -> Map.entry(rs.getLong("territory_id"), rs.getString("country_code")))
                .list().stream()
                .collect(Collectors.toUnmodifiableMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    @Override
    public Map<String, Set<String>> regionCountries(Set<String> regionCodes) {
        return jdbc.sql(sql.get("grant.regionCountries")).param("regionCodes", List.copyOf(regionCodes))
                .query((rs, n) -> Map.entry(rs.getString("region_code"), rs.getString("country_code")))
                .list().stream()
                .collect(Collectors.groupingBy(Map.Entry::getKey, Collectors.mapping(Map.Entry::getValue, Collectors.toUnmodifiableSet())));
    }

    @Override
    public Set<String> existingCountries(Set<String> countryCodes) {
        return strings("grant.existingCountries", "countryCodes", countryCodes);
    }

    @Override
    public Set<String> existingRegions(Set<String> regionCodes) {
        return strings("grant.existingRegions", "regionCodes", regionCodes);
    }

    @Override
    public Set<String> existingBusinessUnits(Set<String> buCodes) {
        return strings("grant.existingBusinessUnits", "buCodes", buCodes);
    }

    @Override
    public StoredGrant insertGrant(long userId, String roleCode, GeoScopeRequest geo, Set<String> buCodes, Instant validTo,
                                   long grantedBy, String reason) {
        record Inserted(long grantId, Instant validFrom) { }
        var inserted = jdbc.sql(sql.get("grant.insertGrant"))
                .param("userId", userId)
                .param("roleCode", roleCode)
                .param("validTo", validTo == null ? null : OffsetDateTime.ofInstant(validTo, java.time.ZoneOffset.UTC))
                .param("grantedBy", grantedBy)
                .param("reason", reason)
                .query((rs, n) -> new Inserted(rs.getLong("grant_id"), instant(rs, "valid_from")))
                .single();
        var insertScope = sql.get("grant.insertGeoScope");
        geo.regionCodes().forEach(r -> geoRow(insertScope, inserted.grantId(), r, null, null));
        geo.countryCodes().forEach(c -> geoRow(insertScope, inserted.grantId(), null, c, null));
        geo.territoryIds().forEach(t -> geoRow(insertScope, inserted.grantId(), null, null, t));
        buCodes.forEach(bu -> jdbc.sql(sql.get("grant.insertBuScope")).param("grantId", inserted.grantId()).param("buCode", bu).update());
        return new StoredGrant(inserted.grantId(), userId, roleCode, inserted.validFrom(), validTo, grantedBy, null, geo, buCodes);
    }

    @Override
    public Optional<StoredGrant> findGrant(long grantId) {
        return withScopes(jdbc.sql(sql.get("grant.findGrant")).param("grantId", grantId).query(GRANT_HEAD).list()).stream().findFirst();
    }

    @Override
    public List<StoredGrant> grantsOfUser(long userId) {
        return withScopes(jdbc.sql(sql.get("grant.grantsOfUser")).param("userId", userId).query(GRANT_HEAD).list());
    }

    @Override
    public boolean revoke(long grantId, long revokedBy, String reason) {
        return jdbc.sql(sql.get("grant.revokeGrant"))
                .param("grantId", grantId).param("revokedBy", revokedBy).param("reason", reason)
                .query(Integer.class).optional().isPresent();
    }

    // ------------------------------------------------------------------------------------------------ helpers

    private record GrantHead(long grantId, long userId, String roleCode, Instant validFrom, Instant validTo, Long grantedBy, Instant revokedAt) { }

    private static final RowMapper<GrantHead> GRANT_HEAD = (rs, n) -> new GrantHead(
            rs.getLong("grant_id"), rs.getLong("user_id"), rs.getString("role_code"),
            instant(rs, "valid_from"), instant(rs, "valid_to"),
            rs.getObject("granted_by_user_id", Long.class), instant(rs, "revoked_at"));

    private List<StoredGrant> withScopes(List<GrantHead> heads) {
        if (heads.isEmpty()) {
            return List.of();
        }
        var ids = heads.stream().map(GrantHead::grantId).toList();
        record GeoRow(long grantId, String region, String country, Long territory) { }
        var geo = jdbc.sql(sql.get("grant.geoScopesOfGrants")).param("grantIds", ids)
                .query((rs, n) -> new GeoRow(rs.getLong("grant_id"), rs.getString("region_code"),
                        rs.getString("country_code"), rs.getObject("territory_id", Long.class)))
                .list().stream()
                .collect(Collectors.groupingBy(GeoRow::grantId));
        Map<Long, Set<String>> bus = grouped("grant.buScopesOfGrants", ids, rs -> rs.getString("bu_code"));
        return heads.stream().map(h -> {
            var rows = geo.getOrDefault(h.grantId(), List.of());
            var request = new GeoScopeRequest(
                    rows.stream().map(GeoRow::region).filter(java.util.Objects::nonNull).collect(Collectors.toSet()),
                    rows.stream().map(GeoRow::country).filter(java.util.Objects::nonNull).collect(Collectors.toSet()),
                    rows.stream().map(GeoRow::territory).filter(java.util.Objects::nonNull).collect(Collectors.toSet()));
            return new StoredGrant(h.grantId(), h.userId(), h.roleCode(), h.validFrom(), h.validTo(), h.grantedBy(),
                    h.revokedAt(), request, bus.getOrDefault(h.grantId(), Set.of()));
        }).toList();
    }

    private void geoRow(String insert, long grantId, String region, String country, Long territory) {
        jdbc.sql(insert).param("grantId", grantId).param("regionCode", region)
                .param("countryCode", country).param("territoryId", territory).update();
    }

    private Set<String> strings(String statement, String param, Set<String> values) {
        if (values.isEmpty()) {
            return Set.of();
        }
        return Set.copyOf(jdbc.sql(sql.get(statement)).param(param, List.copyOf(values)).query(String.class).list());
    }

    @FunctionalInterface
    private interface Column<T> {
        T read(ResultSet rs) throws SQLException;
    }

    private <T> Map<Long, Set<T>> grouped(String statement, List<Long> grantIds, Column<T> column) {
        return jdbc.sql(sql.get(statement)).param("grantIds", grantIds)
                .query((rs, n) -> Map.entry(rs.getLong("grant_id"), column.read(rs)))
                .list().stream()
                .collect(Collectors.groupingBy(Map.Entry::getKey,
                        Collectors.mapping(Map.Entry::getValue, Collectors.toCollection(HashSet::new))));
    }

    private static Instant instant(ResultSet rs, String column) throws SQLException {
        var value = rs.getObject(column, OffsetDateTime.class);
        return value == null ? null : value.toInstant();
    }
}
