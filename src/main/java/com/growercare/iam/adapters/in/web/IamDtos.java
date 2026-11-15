package com.growercare.iam.adapters.in.web;

import com.growercare.iam.domain.StoredGrant;
import com.growercare.security.EffectiveGrant;
import com.growercare.security.GcPrincipal;
import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import java.util.List;
import java.util.Set;

/** Public JSON contracts of identity-access-service. IDs are strings (64-bit safe for JavaScript clients). */
final class IamDtos {

    private IamDtos() { }

    static final String ID = "^[1-9][0-9]{0,18}$";

    record CreateGrantRequest(
            @NotBlank @Pattern(regexp = ID) String userId,
            @NotBlank @Pattern(regexp = "^[A-Z][A-Z_]{1,39}$") String roleCode,
            @Size(max = 10) Set<@Pattern(regexp = "^[A-Z]{2,8}$") String> regionCodes,
            @Size(max = 50) Set<@Pattern(regexp = "^[A-Z]{2}$") String> countryCodes,
            @Size(max = 200) Set<@Pattern(regexp = ID) String> territoryIds,
            @Size(max = 10) Set<@Pattern(regexp = "^[A-Z]{2,8}$") String> buCodes,
            @Future Instant validTo,
            @NotBlank @Size(max = 300) String reason) { }

    record GrantView(
            String grantId,
            String userId,
            String roleCode,
            List<String> regionCodes,
            List<String> countryCodes,
            List<String> territoryIds,
            List<String> buCodes,
            Instant validFrom,
            Instant validTo,
            String grantedByUserId,
            Instant revokedAt) {

        static GrantView of(StoredGrant g) {
            return new GrantView(
                    Long.toString(g.grantId()), Long.toString(g.userId()), g.roleCode(),
                    g.geo().regionCodes().stream().sorted().toList(),
                    g.geo().countryCodes().stream().sorted().toList(),
                    g.geo().territoryIds().stream().sorted().map(String::valueOf).toList(),
                    g.buCodes().stream().sorted().toList(),
                    g.validFrom(), g.validTo(),
                    g.grantedByUserId() == null ? null : Long.toString(g.grantedByUserId()),
                    g.revokedAt());
        }
    }

    record EffectiveGrantView(
            String grantId,
            String roleCode,
            String scopeKind,
            String piiClearance,
            List<String> permissions,
            List<String> countryCodes,
            List<String> territoryIds,
            List<String> buCodes,
            Instant validTo) {

        static EffectiveGrantView of(EffectiveGrant g) {
            return new EffectiveGrantView(
                    Long.toString(g.grantId()), g.roleCode(), g.scopeKind().name(), g.piiClearance().name(),
                    g.permissions().stream().sorted().toList(),
                    g.countries().stream().sorted().toList(),
                    g.territories().stream().sorted().map(String::valueOf).toList(),
                    g.buCodes().stream().sorted().toList(),
                    g.validTo());
        }
    }

    record MeView(String userId, String userType, String homeCountry, String partnerOrgId, List<EffectiveGrantView> grants) {

        static MeView of(GcPrincipal p) {
            return new MeView(Long.toString(p.userId()), p.userType().name(), p.homeCountry(),
                    p.partnerOrg().map(String::valueOf).orElse(null),
                    p.grants().stream().map(EffectiveGrantView::of).toList());
        }
    }
}
