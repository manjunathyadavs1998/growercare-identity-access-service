package com.growercare.iam.application;

import com.growercare.common.error.BusinessRuleException;
import com.growercare.common.error.ConflictException;
import com.growercare.common.error.ErrorCode;
import com.growercare.common.error.PermissionDeniedException;
import com.growercare.common.web.TraceIds;
import com.growercare.iam.application.port.AccessRepository;
import com.growercare.iam.application.port.AuditLog;
import com.growercare.iam.domain.GeoScopeRequest;
import com.growercare.iam.domain.SelfRegistrationRules;
import com.growercare.outbox.OutboxWriter;
import com.growercare.security.GcPrincipal;
import com.growercare.security.PrincipalResolver;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * SPEC-IAM-03: a grower who signed up on Keycloak's registration page gets a GrowerCare account on the first call.
 * Only ever a GROWER with one GROWER grant (OWN) in the chosen country (D3); idempotent per subject (D6).
 */
@Service
public class SelfRegistration {

    private static final String OUTBOX = "iam.outbox";

    /** The account as {@code /me} shows it, and whether this call created it. */
    public record Result(GcPrincipal principal, boolean created) { }

    private final AccessRepository repository;
    private final AuditLog audit;
    private final OutboxWriter outbox;
    private final PrincipalResolver principals;
    private final TransactionTemplate tx;

    public SelfRegistration(AccessRepository repository, AuditLog audit, OutboxWriter outbox, PrincipalResolver principals,
                            TransactionTemplate tx) {
        this.repository = repository;
        this.audit = audit;
        this.outbox = outbox;
        this.principals = principals;
        this.tx = tx;
    }

    public Result register(UUID subject, String username, String rawCountry, String rawName) {
        var country = SelfRegistrationRules.countryCode(rawCountry);
        var name = SelfRegistrationRules.displayName(rawName);

        var existing = repository.findUserBySubject(subject);
        if (existing.isPresent()) {
            return replay(existing.get().homeCountry(), country, subject);
        }
        var phone = SelfRegistrationRules.phone(username);
        var callingCode = repository.callingCode(country)
                .orElseThrow(() -> new BusinessRuleException("iam.country-unavailable", "Sign-up is not open in " + country));
        SelfRegistrationRules.requireCallingCode(phone, callingCode);

        Long userId = tx.execute(status -> {
            var id = repository.insertSelfRegisteredUser(subject, country, name, SelfRegistrationRules.lastFour(phone));
            if (id.isEmpty()) {
                return null;                                    // a concurrent first call for this subject won
            }
            var grant = repository.insertGrant(id.get(), SelfRegistrationRules.ROLE,
                    new GeoScopeRequest(Set.of(), Set.of(country), Set.of()), Set.of(), null, null, SelfRegistrationRules.REASON);
            audit.success(id.get(), "user.self-register", "USER", Long.toString(id.get()), country, SelfRegistrationRules.REASON);
            // the existing grant event (ids and codes only): consumers treat it like any other new grant
            outbox.append(OUTBOX, new OutboxWriter.Event("grant", Long.toString(grant.grantId()), "iam.grant.created", Map.of(
                    "grantId", Long.toString(grant.grantId()),
                    "userId", Long.toString(id.get()),
                    "subject", subject.toString(),
                    "roleCode", SelfRegistrationRules.ROLE,
                    "actorUserId", Long.toString(id.get()))), TraceIds.currentOrNull());
            return id.get();
        });
        if (userId == null) {
            return replay(repository.findUserBySubject(subject).orElseThrow().homeCountry(), country, subject);
        }
        return new Result(principals.resolve(subject).orElseThrow(), true);
    }

    /** R61: the same subject again → its account; another country → 409 (the country is fixed once chosen). */
    private Result replay(String homeCountry, String requested, UUID subject) {
        if (!homeCountry.equals(requested)) {
            throw new ConflictException(ErrorCode.DUPLICATE, "This account is already registered in " + homeCountry);
        }
        // R67: a suspended or deactivated account resolves to no principal; self-registration never revives it
        return new Result(principals.resolve(subject).orElseThrow(() -> new PermissionDeniedException("self-registration")), false);
    }
}
