package com.growercare.iam.application;

import com.growercare.common.error.NotFoundException;
import com.growercare.iam.application.port.AccessRepository;
import com.growercare.iam.application.port.ReferenceRepository;
import com.growercare.iam.application.port.ReferenceRepository.GrantableRole;
import com.growercare.iam.application.port.ReferenceRepository.Territory;
import com.growercare.iam.domain.GrantRules;
import com.growercare.security.EffectiveGrant;
import com.growercare.security.RequiresPermission;
import com.growercare.security.ScopeKind;
import com.growercare.security.web.CurrentPrincipal;
import java.time.Clock;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** SPEC-IAM-04: territories, grantable roles and assignable staff for the UI. */
@Service
public class UiReferenceData {

    public static final String PERM_CASE_ASSIGN = "case:assign";

    /** R104: a staff member and their roles that let them take the case. */
    public record AssignableStaff(long userId, String displayName, List<String> roleCodes) { }

    private final ReferenceRepository reference;
    private final AccessRepository access;
    private final Clock clock;

    public UiReferenceData(ReferenceRepository reference, AccessRepository access, Clock clock) {
        this.reference = reference;
        this.access = access;
        this.clock = clock;
    }

    /** R100/R101: the home country and every country a grant covers; anything else is 404. */
    @Transactional(readOnly = true)
    public List<Territory> territories(String country) {
        var principal = CurrentPrincipal.require();
        var wanted = country == null ? principal.homeCountry() : country;
        var visible = new HashSet<String>();
        visible.add(principal.homeCountry());
        boolean global = false;
        for (EffectiveGrant g : principal.grants()) {
            if (!g.isActiveAt(clock.instant())) {
                continue;
            }
            global |= g.scopeKind() == ScopeKind.GLOBAL;
            visible.addAll(g.countries());
            if (!g.territories().isEmpty()) {
                visible.addAll(access.territoryCountries(g.territories()).values());
            }
        }
        if (!(global || visible.contains(wanted)) || !reference.countryExists(wanted)) {
            throw new NotFoundException("Country");
        }
        return reference.territories(wanted);
    }

    /** R102: roles whose level is not above the admin's strongest grant:create grant (SPEC-IAM-01 delegation). */
    @Transactional(readOnly = true)
    @RequiresPermission(GrantRules.PERM_GRANT_CREATE)
    public List<GrantableRole> grantableRoles() {
        int level = CurrentPrincipal.require().grantsWith(GrantRules.PERM_GRANT_CREATE, clock.instant())
                .mapToInt(EffectiveGrant::roleLevel).max().orElse(0);
        return reference.rolesUpTo(level);
    }

    /**
     * R104/R105: who could take a case in {@code territoryId}/{@code buCode}. Some {@code case:assign} grant of the caller must
     * cover both the territory (geo) and the BU (convention 1: role + geo + BU); otherwise 404, as for any out-of-scope resource.
     */
    @Transactional(readOnly = true)
    @RequiresPermission(PERM_CASE_ASSIGN)
    public List<AssignableStaff> assignable(long territoryId, String buCode) {
        var principal = CurrentPrincipal.require();
        var country = access.territoryCountries(Set.of(territoryId)).get(territoryId);
        boolean inScope = country != null && principal.grantsWith(PERM_CASE_ASSIGN, clock.instant())
                .anyMatch(g -> g.coversGeo(country, territoryId) && g.coversBu(buCode));
        if (!inScope) {
            throw new NotFoundException("Territory");
        }
        var byUser = new LinkedHashMap<Long, AssignableStaff>();
        for (var row : reference.assignable(territoryId, country, buCode)) {
            byUser.computeIfAbsent(row.userId(), id -> new AssignableStaff(id, row.displayName(), new ArrayList<>()))
                    .roleCodes().add(row.roleCode());
        }
        return byUser.values().stream().map(s -> new AssignableStaff(s.userId(), s.displayName(), List.copyOf(s.roleCodes()))).toList();
    }
}
