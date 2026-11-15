package com.growercare.iam.adapters.out.persistence;

import com.growercare.iam.application.port.AccessRepository;
import com.growercare.iam.application.port.PrincipalDirectory;
import com.growercare.iam.domain.UserAccount;
import com.growercare.security.GcPrincipal;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Component;

/**
 * IAM resolves principals straight from its own database (it is the source of truth for grants).
 * Inactive accounts resolve to empty (401 at the edge).
 */
@Component
class JdbcPrincipalResolver implements PrincipalDirectory {

    private final AccessRepository repository;

    JdbcPrincipalResolver(AccessRepository repository) {
        this.repository = repository;
    }

    @Override
    public Optional<GcPrincipal> resolve(UUID subject) {
        return repository.findUserBySubject(subject).filter(UserAccount::isActive).map(this::principalOf);
    }

    /** IAM-R18: by IAM user id (assignee validation in case-service). */
    @Override
    public Optional<GcPrincipal> resolveById(long userId) {
        return repository.findUser(userId).filter(UserAccount::isActive).map(this::principalOf);
    }

    private GcPrincipal principalOf(UserAccount u) {
        return new GcPrincipal(u.userId(), u.subject(), u.userType(), u.homeCountry(), u.partnerOrgId(),
                repository.effectiveGrants(u.userId()));
    }
}
