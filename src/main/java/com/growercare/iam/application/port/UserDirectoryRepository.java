package com.growercare.iam.application.port;

import java.util.List;
import java.util.Optional;
import java.util.Set;

/** SPEC-IAM-02: read side of the user directory (hand-written SQL, ADR-013). */
public interface UserDirectoryRepository {

    /** A directory row; never the phone number or its HMAC, only the last four digits. */
    record DirectoryUser(long userId, String userType, String homeCountry, Long partnerOrgId, String displayName,
                         String phoneLast4, String status) { }

    /**
     * Visibility: {@code allCountries} or {@code countries}; grower names are matched only in {@code allFullCountries} or
     * {@code fullCountries} (D6). {@code namePrefix} is already lower-case; {@code qUserId} is set when q is an id.
     */
    record Search(boolean allCountries, Set<String> countries, boolean allFullCountries, Set<String> fullCountries,
                  String country, String userType, String status, String namePrefix, Long qUserId, long afterUserId, int limit) { }

    List<DirectoryUser> search(Search search);

    Optional<DirectoryUser> user(long userId);

    /** SPEC-IAM-05: a staff member's name and home country. */
    record StaffName(long userId, String displayName, String homeCountry) { }

    List<StaffName> staffNames(java.util.Collection<Long> ids);

    /** SPEC-IAM-05: who to email (no password, no phone). */
    record Contact(long userId, String userType, String status, String email, String displayName) { }

    Optional<Contact> contact(long userId);
}
