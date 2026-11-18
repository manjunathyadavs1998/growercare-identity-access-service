package com.growercare.iam.adapters.in.web;

import com.growercare.common.error.NotFoundException;
import com.growercare.iam.adapters.in.web.IamDtos.GrantView;
import com.growercare.iam.application.UserDirectory;
import com.growercare.iam.application.port.UserDirectoryRepository.DirectoryUser;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.util.List;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** SPEC-IAM-02 §3: the user directory for administrators (read-only, D1). */
@RestController
@Validated
class UserDirectoryController {

    record UserSummary(String userId, String userType, String homeCountry, String partnerOrgId, String displayName,
                       String phoneLast4, String status) {

        static UserSummary of(DirectoryUser u) {
            return new UserSummary(Long.toString(u.userId()), u.userType(), u.homeCountry(),
                    u.partnerOrgId() == null ? null : Long.toString(u.partnerOrgId()), u.displayName(), u.phoneLast4(), u.status());
        }
    }

    record UserPage(List<UserSummary> items, String nextCursor) { }

    record UserView(String userId, String userType, String homeCountry, String partnerOrgId, String displayName,
                    String phoneLast4, String status, List<GrantView> grants) { }

    private final UserDirectory directory;

    UserDirectoryController(UserDirectory directory) {
        this.directory = directory;
    }

    @GetMapping("/users")
    UserPage search(@RequestParam(required = false) @Size(max = 120) String q,
                    @RequestParam(required = false) @Pattern(regexp = "^(GROWER|PARTNER|STAFF)$") String type,
                    @RequestParam(required = false) @Pattern(regexp = "^[A-Z]{2}$") String country,
                    @RequestParam(required = false) @Pattern(regexp = "^(ACTIVE|SUSPENDED|DEACTIVATED)$") String status,
                    @RequestParam(required = false) String cursor,
                    @RequestParam(defaultValue = "20") @Min(1) @Max(100) int limit) {
        var page = directory.search(new UserDirectory.Query(q, type, country, status, cursor, limit));
        return new UserPage(page.items().stream().map(UserSummary::of).toList(), page.nextCursor());
    }

    /** R81: malformed ids are indistinguishable from unknown ones (404). */
    @GetMapping("/users/{userId}")
    UserView user(@PathVariable String userId) {
        long id;
        try {
            id = userId.matches(IamDtos.ID) ? Long.parseLong(userId) : -1;
        } catch (NumberFormatException e) {
            id = -1;
        }
        if (id < 0) {
            throw new NotFoundException("User");
        }
        var found = directory.user(id);
        var s = UserSummary.of(found.user());
        return new UserView(s.userId(), s.userType(), s.homeCountry(), s.partnerOrgId(), s.displayName(), s.phoneLast4(), s.status(),
                found.grants().stream().map(GrantView::of).toList());
    }
}
