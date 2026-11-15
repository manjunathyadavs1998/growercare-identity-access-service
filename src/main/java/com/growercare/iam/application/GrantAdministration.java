package com.growercare.iam.application;

import com.growercare.common.error.BusinessRuleException;
import com.growercare.common.error.ConflictException;
import com.growercare.common.error.GcException;
import com.growercare.common.error.NotFoundException;
import com.growercare.common.error.ValidationException;
import com.growercare.common.web.TraceIds;
import com.growercare.iam.application.port.AccessRepository;
import com.growercare.iam.application.port.AuditLog;
import com.growercare.iam.domain.CreateGrantCommand;
import com.growercare.iam.domain.GeoScopeRequest;
import com.growercare.iam.domain.Geography;
import com.growercare.iam.domain.GrantRules;
import com.growercare.iam.domain.RoleDefinition;
import com.growercare.iam.domain.StoredGrant;
import com.growercare.iam.domain.UserAccount;
import com.growercare.outbox.OutboxWriter;
import com.growercare.security.GcPrincipal;
import com.growercare.security.RequiresPermission;
import com.growercare.security.web.CurrentPrincipal;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use cases: grant a role, revoke a grant, list a user's grants (ACC-1, ACC-2, ACC-6).
 * <ol>
 *   <li>function level: {@link RequiresPermission} (403);</li>
 *   <li>object level: the target user must be inside the admin's scope, otherwise 404;</li>
 *   <li>business rules: {@link GrantRules} (422/409), every denial audited in its own transaction;</li>
 *   <li>change + audit + outbox event in one transaction.</li>
 * </ol>
 */
@Service
public class GrantAdministration {

    private static final String OUTBOX = "iam.outbox";

    private final AccessRepository repository;
    private final AuditLog audit;
    private final OutboxWriter outbox;
    private final Clock clock;

    public GrantAdministration(AccessRepository repository, AuditLog audit, OutboxWriter outbox, Clock clock) {
        this.repository = repository;
        this.audit = audit;
        this.outbox = outbox;
        this.clock = clock;
    }

    @Transactional
    @RequiresPermission(GrantRules.PERM_GRANT_CREATE)
    public StoredGrant create(CreateGrantCommand cmd) {
        var admin = CurrentPrincipal.require();
        var now = clock.instant();
        var target = visibleUser(admin, GrantRules.PERM_GRANT_CREATE, cmd.targetUserId());
        var role = repository.findRole(cmd.roleCode())
                .orElseThrow(() -> ValidationException.of("roleCode", "unknown role"));
        validateReferences(cmd.geo(), cmd.buCodes());
        var geography = geographyOf(cmd.geo());

        audited(admin, "grant.create", target, () -> GrantRules.checkCreate(admin, now, target, role, cmd,
                repository.activeRoleCodes(target.userId()), repository.sodConflictsOf(role.roleCode()), geography));

        var grant = repository.insertGrant(target.userId(), role.roleCode(), cmd.geo(), cmd.buCodes(), cmd.validTo(),
                admin.userId(), cmd.reason());
        audit.success(admin.userId(), "grant.create", "GRANT", Long.toString(grant.grantId()), target.homeCountry(), cmd.reason());
        outbox.append(OUTBOX, event("iam.grant.created", grant, target, admin), TraceIds.currentOrNull());
        return grant;
    }

    @Transactional
    @RequiresPermission(GrantRules.PERM_GRANT_REVOKE)
    public StoredGrant revoke(long grantId, String reason) {
        if (reason == null || reason.isBlank()) {
            throw ValidationException.of("reason", "must not be blank");
        }
        var admin = CurrentPrincipal.require();
        var grant = repository.findGrant(grantId).orElseThrow(() -> new NotFoundException("Grant"));
        var target = visibleUser(admin, GrantRules.PERM_GRANT_REVOKE, grant.userId(), "Grant");
        RoleDefinition role = repository.findRole(grant.roleCode()).orElseThrow(() -> new IllegalStateException("Role missing"));
        var geography = geographyOf(grant.geo());

        audited(admin, "grant.revoke", target, () -> {
            if (grant.isRevoked()) {
                throw new BusinessRuleException("grant.already-revoked", "The grant is already revoked");
            }
            GrantRules.checkDelegation(admin, clock.instant(), GrantRules.PERM_GRANT_REVOKE, role, grant.geo(), geography);
        });
        if (!repository.revoke(grantId, admin.userId(), reason)) {
            throw new BusinessRuleException("grant.already-revoked", "The grant is already revoked");
        }
        audit.success(admin.userId(), "grant.revoke", "GRANT", Long.toString(grantId), target.homeCountry(), reason);
        outbox.append(OUTBOX, event("iam.grant.revoked", grant, target, admin), TraceIds.currentOrNull());
        return repository.findGrant(grantId).orElseThrow();
    }

    @Transactional(readOnly = true)
    @RequiresPermission(GrantRules.PERM_GRANT_READ)
    public List<StoredGrant> grantsOfUser(long userId) {
        var viewer = CurrentPrincipal.require();
        visibleUser(viewer, GrantRules.PERM_GRANT_READ, userId);
        return repository.grantsOfUser(userId);
    }

    // ------------------------------------------------------------------------------------------------ helpers

    private UserAccount visibleUser(GcPrincipal admin, String permission, long userId) {
        return visibleUser(admin, permission, userId, "User");
    }

    /** Users outside the admin's country scope are reported as not found (no existence leak). */
    private UserAccount visibleUser(GcPrincipal admin, String permission, long userId, String resourceType) {
        return repository.findUser(userId)
                .filter(u -> GrantRules.canAdminister(admin, clock.instant(), permission, u))
                .orElseThrow(() -> new NotFoundException(resourceType));
    }

    private void audited(GcPrincipal admin, String action, UserAccount target, Runnable rules) {
        try {
            rules.run();
        } catch (BusinessRuleException | ConflictException e) {
            var why = e instanceof BusinessRuleException b ? b.rule() : ((GcException) e).code().name();
            audit.denied(admin.userId(), action, "USER", Long.toString(target.userId()), target.homeCountry(), why);
            throw e;
        }
    }

    private void validateReferences(GeoScopeRequest geo, Set<String> buCodes) {
        var errors = new ArrayList<ValidationException.FieldError>();
        missing(geo.countryCodes(), repository::existingCountries).forEach(c -> errors.add(new ValidationException.FieldError("countryCodes", "unknown country " + c)));
        missing(geo.regionCodes(), repository::existingRegions).forEach(r -> errors.add(new ValidationException.FieldError("regionCodes", "unknown region " + r)));
        missing(buCodes, repository::existingBusinessUnits).forEach(b -> errors.add(new ValidationException.FieldError("buCodes", "unknown business unit " + b)));
        var knownTerritories = geo.territoryIds().isEmpty() ? Map.<Long, String>of() : repository.territoryCountries(geo.territoryIds());
        geo.territoryIds().stream().filter(t -> !knownTerritories.containsKey(t)).sorted()
                .forEach(t -> errors.add(new ValidationException.FieldError("territoryIds", "unknown territory " + t)));
        if (!errors.isEmpty()) {
            throw new ValidationException(errors);
        }
    }

    private static <T extends Comparable<T>> List<T> missing(Set<T> requested, Function<Set<T>, Set<T>> existing) {
        if (requested.isEmpty()) {
            return List.of();
        }
        var found = existing.apply(requested);
        return requested.stream().filter(v -> !found.contains(v)).sorted().toList();
    }

    private Geography geographyOf(GeoScopeRequest geo) {
        return new Geography(
                geo.territoryIds().isEmpty() ? Map.of() : repository.territoryCountries(geo.territoryIds()),
                geo.regionCodes().isEmpty() ? Map.of() : repository.regionCountries(geo.regionCodes()));
    }

    private static OutboxWriter.Event event(String type, StoredGrant grant, UserAccount target, GcPrincipal admin) {
        // No PII in events: ids and codes only.
        return new OutboxWriter.Event("grant", Long.toString(grant.grantId()), type, Map.of(
                "grantId", Long.toString(grant.grantId()),
                "userId", Long.toString(target.userId()),
                "subject", target.subject().toString(),
                "roleCode", grant.roleCode(),
                "actorUserId", Long.toString(admin.userId())));
    }
}
