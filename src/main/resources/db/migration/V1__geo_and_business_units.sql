-- =====================================================================================================
-- identity-access-service · V1 · Geography and business-unit masters (BRD §2)
-- Master data is owned by control-plane-service; IAM keeps a replica because grants reference it with FKs.
-- IDs are therefore assigned upstream (no identity columns here).
-- Placeholders: ${app_role}
-- =====================================================================================================
GRANT USAGE ON SCHEMA iam TO ${app_role};

CREATE TABLE iam.region (
    region_code  varchar(8)  PRIMARY KEY CHECK (region_code ~ '^[A-Z]{2,8}$'),
    name         varchar(80) NOT NULL
);

CREATE TABLE iam.country (
    country_code   char(2)     PRIMARY KEY CHECK (country_code ~ '^[A-Z]{2}$'),
    region_code    varchar(8)  NOT NULL REFERENCES iam.region (region_code),
    name           varchar(80) NOT NULL,
    country_ix     smallint    NOT NULL UNIQUE CHECK (country_ix BETWEEN 0 AND 63),   -- 6-bit index in case_id (ID-5)
    case_no_cc     smallint    NOT NULL UNIQUE CHECK (case_no_cc BETWEEN 10 AND 99),  -- public case_no slot
    time_zone      varchar(64) NOT NULL,
    currency_code  char(3)     NOT NULL CHECK (currency_code ~ '^[A-Z]{3}$'),
    default_locale varchar(16) NOT NULL,
    active         boolean     NOT NULL DEFAULT true
);
CREATE INDEX country_region_ix ON iam.country (region_code);

-- Hierarchy STATE > DISTRICT > SALES_AREA. The composite FK forces a parent to be in the same country.
CREATE TABLE iam.territory (
    territory_id        bigint      PRIMARY KEY,
    country_code        char(2)     NOT NULL REFERENCES iam.country (country_code),
    parent_territory_id bigint,
    territory_code      varchar(32) NOT NULL,
    name                varchar(120) NOT NULL,
    territory_level     varchar(16) NOT NULL CHECK (territory_level IN ('STATE', 'DISTRICT', 'SALES_AREA')),
    CONSTRAINT territory_code_uq UNIQUE (country_code, territory_code),
    CONSTRAINT territory_id_country_uq UNIQUE (territory_id, country_code),
    CONSTRAINT territory_parent_fk FOREIGN KEY (parent_territory_id, country_code)
        REFERENCES iam.territory (territory_id, country_code),
    CONSTRAINT territory_not_own_parent CHECK (parent_territory_id IS DISTINCT FROM territory_id)
);
CREATE INDEX territory_parent_ix ON iam.territory (parent_territory_id);

CREATE TABLE iam.business_unit (
    bu_code varchar(8)  PRIMARY KEY CHECK (bu_code ~ '^[A-Z]{2,8}$'),
    name    varchar(80) NOT NULL
);
