package com.growercare.iam.adapters.in.web;

import com.growercare.iam.adapters.in.web.IamDtos.CreateGrantRequest;
import com.growercare.iam.adapters.in.web.IamDtos.GrantView;
import com.growercare.iam.adapters.in.web.IamDtos.MeView;
import com.growercare.iam.application.GrantAdministration;
import com.growercare.iam.domain.CreateGrantCommand;
import com.growercare.iam.domain.GeoScopeRequest;
import com.growercare.security.web.CurrentPrincipal;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.net.URI;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Self-service identity and grant administration. Controllers only translate HTTP ⇄ commands; authorization and
 * rules live in {@link GrantAdministration}.
 */
@RestController
@Validated
class GrantController {

    private final GrantAdministration grants;

    GrantController(GrantAdministration grants) {
        this.grants = grants;
    }

    /** The caller's identity and effective grants. */
    @GetMapping("/me")
    MeView me() {
        return MeView.of(CurrentPrincipal.require());
    }

    @PostMapping("/grants")
    ResponseEntity<GrantView> create(@Valid @RequestBody CreateGrantRequest body) {
        var command = new CreateGrantCommand(
                Long.parseLong(body.userId()),
                body.roleCode(),
                new GeoScopeRequest(body.regionCodes(), body.countryCodes(), longs(body.territoryIds())),
                body.buCodes(),
                body.validTo(),
                body.reason().strip());
        var created = grants.create(command);
        return ResponseEntity.created(URI.create("/grants/" + created.grantId())).body(GrantView.of(created));
    }

    @DeleteMapping("/grants/{grantId}")
    GrantView revoke(@PathVariable @Pattern(regexp = IamDtos.ID) String grantId,
                     @RequestParam @NotBlank @Size(max = 300) String reason) {
        return GrantView.of(grants.revoke(Long.parseLong(grantId), reason.strip()));
    }

    @GetMapping("/users/{userId}/grants")
    List<GrantView> grantsOfUser(@PathVariable @Pattern(regexp = IamDtos.ID) String userId) {
        return grants.grantsOfUser(Long.parseLong(userId)).stream().map(GrantView::of).toList();
    }

    private static Set<Long> longs(Set<String> ids) {
        return Optional.ofNullable(ids).orElse(Set.of()).stream().map(Long::parseLong).collect(Collectors.toSet());
    }
}
