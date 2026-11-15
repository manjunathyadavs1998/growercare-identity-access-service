package com.growercare.iam.domain;

import com.growercare.security.ScopeKind;
import com.growercare.security.UserType;

/** iam.role row. */
public record RoleDefinition(String roleCode, int roleLevel, ScopeKind scopeKind, UserType allowedUserType, boolean privileged) { }
