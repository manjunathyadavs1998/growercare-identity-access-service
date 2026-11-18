package com.growercare.iam.adapters.in.web;

import com.growercare.iam.application.UiReferenceData;
import jakarta.validation.constraints.Pattern;
import java.util.List;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** SPEC-IAM-04 §3: reference data and assignable staff for the UI (ids as strings). */
@RestController
@Validated
class ReferenceController {

    record TerritoryView(String territoryId, String parentTerritoryId, String code, String name, String level) { }

    record RoleView(String roleCode, String name, String scopeKind, String allowedUserType) { }

    record AssignableView(String userId, String displayName, List<String> roleCodes) { }

    private final UiReferenceData reference;

    ReferenceController(UiReferenceData reference) {
        this.reference = reference;
    }

    @GetMapping("/reference/territories")
    List<TerritoryView> territories(@RequestParam(required = false) @Pattern(regexp = "^[A-Z]{2}$") String country) {
        return reference.territories(country).stream()
                .map(t -> new TerritoryView(Long.toString(t.territoryId()),
                        t.parentTerritoryId() == null ? null : Long.toString(t.parentTerritoryId()), t.code(), t.name(), t.level()))
                .toList();
    }

    @GetMapping("/reference/roles")
    List<RoleView> roles() {
        return reference.grantableRoles().stream()
                .map(r -> new RoleView(r.roleCode(), r.name(), r.scopeKind(), r.allowedUserType())).toList();
    }

    @GetMapping("/users/assignable")
    List<AssignableView> assignable(@RequestParam @Pattern(regexp = IamDtos.ID) String territoryId,
                                    @RequestParam @Pattern(regexp = "^[A-Z][A-Z0-9_]{1,15}$") String buCode) {
        long id;
        try {
            id = Long.parseLong(territoryId);
        } catch (NumberFormatException e) {
            throw com.growercare.common.error.ValidationException.of("territoryId", "must be a positive 64-bit id");
        }
        return reference.assignable(id, buCode).stream()
                .map(s -> new AssignableView(Long.toString(s.userId()), s.displayName(), s.roleCodes())).toList();
    }
}
