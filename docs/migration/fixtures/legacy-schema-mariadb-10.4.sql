-- Schema-only Duende/Skoruba compatibility fixture for MariaDB 10.4.34.
-- Contains table definitions only: no rows, credentials, routines or views.
-- AUTO_INCREMENT counters were removed because they are data-dependent.
-- This synthetic fixture is only for disposable migration rehearsal.

SET FOREIGN_KEY_CHECKS=0;

CREATE TABLE `apiresourceclaims` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `type` varchar(200) NOT NULL,
  `apiresourceid` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_apiresourceclaims_apiresourceid_type` (`apiresourceid`,`type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
CREATE TABLE `apiresourceproperties` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `key` varchar(250) NOT NULL,
  `value` varchar(2000) NOT NULL,
  `apiresourceid` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_apiresourceproperties_apiresourceid_key` (`apiresourceid`,`key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `apiresources` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `enabled` tinyint(1) NOT NULL,
  `name` varchar(200) NOT NULL,
  `displayname` varchar(200) DEFAULT 'NULL',
  `description` varchar(1000) DEFAULT 'NULL',
  `created` datetime(6) NOT NULL,
  `updated` datetime(6) DEFAULT NULL,
  `lastaccessed` datetime(6) DEFAULT NULL,
  `noneditable` tinyint(1) NOT NULL,
  `allowedaccesstokensigningalgorithms` varchar(100) DEFAULT NULL,
  `showindiscoverydocument` tinyint(1) NOT NULL DEFAULT 0,
  `requireresourceindicator` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_apiresources_name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `apiresourcescopes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `scope` varchar(200) NOT NULL,
  `apiresourceid` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_apiresourcescopes_apiresourceid_scope` (`apiresourceid`,`scope`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `apiresourcesecrets` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `description` varchar(1000) DEFAULT NULL,
  `value` varchar(4000) NOT NULL,
  `expiration` datetime(6) DEFAULT NULL,
  `type` varchar(250) NOT NULL,
  `created` datetime(6) NOT NULL,
  `apiresourceid` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `ix_apiresourcesecrets_apiresourceid` (`apiresourceid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `apiscopeclaims` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `type` varchar(200) NOT NULL,
  `scopeid` int(11) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_apiscopeclaims_scopeid_type` (`scopeid`,`type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `apiscopeproperties` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `key` varchar(250) NOT NULL,
  `value` varchar(2000) NOT NULL,
  `scopeid` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_apiscopeproperties_scopeid_key` (`scopeid`,`key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `apiscopes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(200) NOT NULL,
  `displayname` varchar(200) DEFAULT NULL,
  `description` varchar(1000) DEFAULT NULL,
  `required` tinyint(1) NOT NULL,
  `emphasize` tinyint(1) NOT NULL,
  `showindiscoverydocument` tinyint(1) NOT NULL,
  `enabled` tinyint(1) NOT NULL DEFAULT 0,
  `created` datetime(6) NOT NULL DEFAULT '1000-01-01 00:00:00.000000',
  `lastaccessed` datetime(6) DEFAULT NULL,
  `noneditable` tinyint(1) NOT NULL DEFAULT 0,
  `updated` datetime(6) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_apiscopes_name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `auditlog` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `event` longtext DEFAULT NULL,
  `source` longtext DEFAULT NULL,
  `category` longtext DEFAULT NULL,
  `subjectidentifier` longtext DEFAULT NULL,
  `subjectname` longtext DEFAULT NULL,
  `subjecttype` longtext DEFAULT NULL,
  `subjectadditionaldata` longtext DEFAULT NULL,
  `action` longtext DEFAULT NULL,
  `data` longtext DEFAULT NULL,
  `created` datetime(6) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `clientclaims` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `type` varchar(250) NOT NULL,
  `value` varchar(250) NOT NULL,
  `clientid` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_clientclaims_clientid_type_value` (`clientid`,`type`,`value`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `clientcorsorigins` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `origin` varchar(150) NOT NULL,
  `clientid` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_clientcorsorigins_clientid_origin` (`clientid`,`origin`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `clientgranttypes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `granttype` varchar(250) NOT NULL,
  `clientid` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_clientgranttypes_clientid_granttype` (`clientid`,`granttype`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `clientidprestrictions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `provider` varchar(200) NOT NULL,
  `clientid` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_clientidprestrictions_clientid_provider` (`clientid`,`provider`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `clientpostlogoutredirecturis` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `postlogoutredirecturi` varchar(400) NOT NULL,
  `clientid` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_clientpostlogoutredirecturis_clientid_postlogoutredirecturi` (`clientid`,`postlogoutredirecturi`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `clientproperties` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `key` varchar(250) NOT NULL,
  `value` varchar(2000) NOT NULL,
  `clientid` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_clientproperties_clientid_key` (`clientid`,`key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `clientredirecturis` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `redirecturi` varchar(400) NOT NULL,
  `clientid` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_clientredirecturis_clientid_redirecturi` (`clientid`,`redirecturi`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `clients` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `enabled` tinyint(1) NOT NULL,
  `clientid` varchar(200) NOT NULL,
  `protocoltype` varchar(200) NOT NULL,
  `requireclientsecret` tinyint(1) NOT NULL,
  `clientname` varchar(200) DEFAULT NULL,
  `description` varchar(1000) DEFAULT NULL,
  `clienturi` varchar(2000) DEFAULT NULL,
  `logouri` varchar(2000) DEFAULT NULL,
  `requireconsent` tinyint(1) NOT NULL,
  `allowrememberconsent` tinyint(1) NOT NULL,
  `alwaysincludeuserclaimsinidtoken` tinyint(1) NOT NULL,
  `requirepkce` tinyint(1) NOT NULL,
  `allowplaintextpkce` tinyint(1) NOT NULL,
  `allowaccesstokensviabrowser` tinyint(1) NOT NULL,
  `frontchannellogouturi` varchar(2000) DEFAULT NULL,
  `frontchannellogoutsessionrequired` tinyint(1) NOT NULL,
  `backchannellogouturi` varchar(2000) DEFAULT NULL,
  `backchannellogoutsessionrequired` tinyint(1) NOT NULL,
  `allowofflineaccess` tinyint(1) NOT NULL,
  `identitytokenlifetime` int(11) NOT NULL,
  `accesstokenlifetime` int(11) NOT NULL,
  `authorizationcodelifetime` int(11) NOT NULL,
  `consentlifetime` int(11) DEFAULT NULL,
  `absoluterefreshtokenlifetime` int(11) NOT NULL,
  `slidingrefreshtokenlifetime` int(11) NOT NULL,
  `refreshtokenusage` int(11) NOT NULL,
  `updateaccesstokenclaimsonrefresh` tinyint(1) NOT NULL,
  `refreshtokenexpiration` int(11) NOT NULL,
  `accesstokentype` int(11) NOT NULL,
  `enablelocallogin` tinyint(1) NOT NULL,
  `includejwtid` tinyint(1) NOT NULL,
  `alwayssendclientclaims` tinyint(1) NOT NULL,
  `clientclaimsprefix` varchar(200) DEFAULT NULL,
  `pairwisesubjectsalt` varchar(200) DEFAULT NULL,
  `created` datetime(6) NOT NULL,
  `updated` datetime(6) DEFAULT NULL,
  `lastaccessed` datetime(6) DEFAULT NULL,
  `userssolifetime` int(11) DEFAULT NULL,
  `usercodetype` varchar(100) DEFAULT NULL,
  `devicecodelifetime` int(11) NOT NULL,
  `noneditable` tinyint(1) NOT NULL,
  `allowedidentitytokensigningalgorithms` varchar(100) DEFAULT NULL,
  `requirerequestobject` tinyint(1) NOT NULL DEFAULT 0,
  `cibalifetime` int(11) DEFAULT NULL,
  `pollinginterval` int(11) DEFAULT NULL,
  `coordinatelifetimewithusersession` tinyint(1) DEFAULT NULL,
  `dpopclockskew` time(6) NOT NULL DEFAULT '00:00:00.000000',
  `dpopvalidationmode` int(11) NOT NULL DEFAULT 0,
  `initiateloginuri` varchar(2000) DEFAULT NULL,
  `pushedauthorizationlifetime` int(11) DEFAULT NULL,
  `requiredpop` tinyint(1) NOT NULL DEFAULT 0,
  `requirepushedauthorization` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_clients_clientid` (`clientid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `clientscopes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `scope` varchar(200) NOT NULL,
  `clientid` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_clientscopes_clientid_scope` (`clientid`,`scope`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `clientsecrets` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `description` varchar(2000) DEFAULT NULL,
  `value` varchar(4000) NOT NULL,
  `expiration` datetime(6) DEFAULT NULL,
  `type` varchar(250) NOT NULL,
  `created` datetime(6) NOT NULL,
  `clientid` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `ix_clientsecrets_clientid` (`clientid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `dataprotectionkeys` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `friendlyname` longtext DEFAULT NULL,
  `xml` longtext DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `devicecodes` (
  `usercode` varchar(200) NOT NULL,
  `devicecode` varchar(200) NOT NULL,
  `subjectid` varchar(200) DEFAULT NULL,
  `clientid` varchar(200) NOT NULL,
  `creationtime` datetime(6) NOT NULL,
  `expiration` datetime(6) NOT NULL,
  `data` longtext NOT NULL,
  `description` varchar(200) DEFAULT NULL,
  `sessionid` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`usercode`),
  UNIQUE KEY `ix_devicecodes_devicecode` (`devicecode`),
  KEY `ix_devicecodes_expiration` (`expiration`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `identityproviders` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `scheme` varchar(200) NOT NULL,
  `displayname` varchar(200) DEFAULT NULL,
  `enabled` tinyint(1) NOT NULL,
  `type` varchar(20) NOT NULL,
  `properties` longtext DEFAULT NULL,
  `created` datetime(6) NOT NULL DEFAULT '1000-01-01 00:00:00.000000',
  `lastaccessed` datetime(6) DEFAULT NULL,
  `noneditable` tinyint(1) NOT NULL DEFAULT 0,
  `updated` datetime(6) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_identityproviders_scheme` (`scheme`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `identityresourceclaims` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `type` varchar(200) NOT NULL,
  `identityresourceid` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_identityresourceclaims_identityresourceid_type` (`identityresourceid`,`type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `identityresourceproperties` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `key` varchar(250) NOT NULL,
  `value` varchar(2000) NOT NULL,
  `identityresourceid` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_identityresourceproperties_identityresourceid_key` (`identityresourceid`,`key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `identityresources` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `enabled` tinyint(1) NOT NULL,
  `name` varchar(200) NOT NULL,
  `displayname` varchar(200) DEFAULT NULL,
  `description` varchar(1000) DEFAULT NULL,
  `required` tinyint(1) NOT NULL,
  `emphasize` tinyint(1) NOT NULL,
  `showindiscoverydocument` tinyint(1) NOT NULL,
  `created` datetime(6) NOT NULL,
  `updated` datetime(6) DEFAULT NULL,
  `noneditable` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_identityresources_name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `keys` (
  `id` varchar(255) NOT NULL,
  `version` int(11) NOT NULL,
  `created` datetime(6) NOT NULL,
  `use` varchar(255) DEFAULT NULL,
  `algorithm` varchar(100) NOT NULL,
  `isx509certificate` tinyint(1) NOT NULL,
  `dataprotected` tinyint(1) NOT NULL,
  `data` longtext NOT NULL,
  PRIMARY KEY (`id`),
  KEY `ix_keys_use` (`use`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `log` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `message` longtext DEFAULT NULL,
  `messagetemplate` longtext DEFAULT NULL,
  `level` varchar(128) DEFAULT NULL,
  `timestamp` datetime(6) NOT NULL,
  `exception` longtext DEFAULT NULL,
  `logevent` longtext DEFAULT NULL,
  `properties` longtext DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `persistedgrants` (
  `key` varchar(200) DEFAULT NULL,
  `type` varchar(50) NOT NULL,
  `subjectid` varchar(200) DEFAULT NULL,
  `clientid` varchar(200) NOT NULL,
  `creationtime` datetime(6) NOT NULL,
  `expiration` datetime(6) DEFAULT NULL,
  `data` longtext NOT NULL,
  `consumedtime` datetime(6) DEFAULT NULL,
  `description` varchar(200) DEFAULT NULL,
  `sessionid` varchar(100) DEFAULT NULL,
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_persistedgrants_key` (`key`),
  KEY `ix_persistedgrants_expiration` (`expiration`),
  KEY `ix_persistedgrants_subjectid_clientid_type` (`subjectid`,`clientid`,`type`),
  KEY `ix_persistedgrants_subjectid_sessionid_type` (`subjectid`,`sessionid`,`type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `pushedauthorizationrequests` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `referencevaluehash` varchar(64) NOT NULL,
  `expiresatutc` datetime(6) NOT NULL,
  `parameters` longtext NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_pushedauthorizationrequests_referencevaluehash` (`referencevaluehash`),
  KEY `ix_pushedauthorizationrequests_expiresatutc` (`expiresatutc`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `roleclaims` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `roleid` varchar(255) NOT NULL,
  `claimtype` longtext DEFAULT NULL,
  `claimvalue` longtext DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `ix_roleclaims_roleid` (`roleid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `roles` (
  `id` varchar(255) NOT NULL,
  `name` varchar(256) DEFAULT NULL,
  `normalizedname` varchar(256) DEFAULT NULL,
  `concurrencystamp` longtext DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `rolenameindex` (`normalizedname`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `serversidesessions` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `key` varchar(100) NOT NULL,
  `scheme` varchar(100) NOT NULL,
  `subjectid` varchar(100) NOT NULL,
  `sessionid` varchar(100) DEFAULT NULL,
  `displayname` varchar(100) DEFAULT NULL,
  `created` datetime(6) NOT NULL,
  `renewed` datetime(6) NOT NULL,
  `expires` datetime(6) DEFAULT NULL,
  `data` longtext NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_serversidesessions_key` (`key`),
  KEY `ix_serversidesessions_displayname` (`displayname`),
  KEY `ix_serversidesessions_expires` (`expires`),
  KEY `ix_serversidesessions_sessionid` (`sessionid`),
  KEY `ix_serversidesessions_subjectid` (`subjectid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `userclaims` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `userid` varchar(255) NOT NULL,
  `claimtype` longtext DEFAULT NULL,
  `claimvalue` longtext DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `ix_userclaims_userid` (`userid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `userlogins` (
  `loginprovider` varchar(255) NOT NULL,
  `providerkey` varchar(255) NOT NULL,
  `providerdisplayname` longtext DEFAULT NULL,
  `userid` varchar(255) NOT NULL,
  PRIMARY KEY (`loginprovider`,`providerkey`),
  KEY `ix_userlogins_userid` (`userid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `userpasskeys` (
  `credentialid` varbinary(1024) NOT NULL,
  `userid` varchar(255) NOT NULL,
  `attestationobject` longblob NOT NULL,
  `clientdatajson` longblob NOT NULL,
  `createdat` datetime(6) NOT NULL,
  `isbackedup` tinyint(1) NOT NULL,
  `isbackupeligible` tinyint(1) NOT NULL,
  `isuserverified` tinyint(1) NOT NULL,
  `name` longtext DEFAULT NULL,
  `publickey` longblob NOT NULL,
  `signcount` int(10) unsigned NOT NULL,
  `transports` longtext NOT NULL,
  PRIMARY KEY (`credentialid`),
  KEY `ix_userpasskeys_userid` (`userid`),
  CONSTRAINT `fk_userpasskeys_users_userid` FOREIGN KEY (`userid`) REFERENCES `users` (`Id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `userroles` (
  `userid` varchar(255) NOT NULL,
  `roleid` varchar(255) NOT NULL,
  PRIMARY KEY (`userid`,`roleid`),
  KEY `ix_userroles_roleid` (`roleid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `users` (
  `id` varchar(255) NOT NULL,
  `username` varchar(256) DEFAULT NULL,
  `normalizedusername` varchar(256) DEFAULT NULL,
  `email` varchar(256) DEFAULT NULL,
  `normalizedemail` varchar(256) DEFAULT NULL,
  `emailconfirmed` tinyint(1) NOT NULL,
  `passwordhash` longtext DEFAULT NULL,
  `securitystamp` longtext DEFAULT NULL,
  `concurrencystamp` longtext DEFAULT NULL,
  `phonenumber` longtext DEFAULT NULL,
  `phonenumberconfirmed` tinyint(1) NOT NULL,
  `twofactorenabled` tinyint(1) NOT NULL,
  `lockoutend` datetime(6) DEFAULT NULL,
  `lockoutenabled` tinyint(1) NOT NULL,
  `accessfailedcount` int(11) NOT NULL,
  `timestamp` timestamp NOT NULL DEFAULT utc_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `usernameindex` (`normalizedusername`),
  KEY `emailindex` (`normalizedemail`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `usertokens` (
  `userid` varchar(255) NOT NULL,
  `loginprovider` varchar(255) NOT NULL,
  `name` varchar(255) NOT NULL,
  `value` longtext DEFAULT NULL,
  PRIMARY KEY (`userid`,`loginprovider`,`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `__efmigrationshistory` (
  `migrationid` varchar(150) NOT NULL,
  `productversion` varchar(32) NOT NULL,
  PRIMARY KEY (`migrationid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

SET FOREIGN_KEY_CHECKS=1;
