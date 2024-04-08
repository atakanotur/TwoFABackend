module.exports = {
  privGroups: [
    {
      id: "USERS",
      name: "User Permissions",
    },
    {
      id: "ROLES",
      name: "Role Permissions",
    },
    {
      id: "AUDITLOGS",
      name: "AuditLogs Permissions",
    },
    {
      id: "ROLEPRIVILEGES",
      name: "RolePrivileges Permissions",
    },
  ],

  privileges: [
    {
      key: "user_view",
      name: "User View",
      group: "USERS",
      description: "User view",
    },
    {
      key: "user_add",
      name: "User Add",
      group: "USERS",
      description: "User add",
    },
    {
      key: "user_update",
      name: "User Update",
      group: "USERS",
      description: "User update",
    },
    {
      key: "user_delete",
      name: "User Delete",
      group: "USERS",
      description: "User delete",
    },
    {
      key: "role_view",
      name: "Role View",
      group: "ROLES",
      description: "Role view",
    },
    {
      key: "role_add",
      name: "Role Add",
      group: "ROLES",
      description: "Role add",
    },
    {
      key: "role_update",
      name: "Role Update",
      group: "ROLES",
      description: "Role update",
    },
    {
      key: "role_delete",
      name: "Role Delete",
      group: "ROLES",
      description: "Role delete",
    },
    {
      key: "auditlogs_view",
      name: "AuditLogs View",
      group: "AUDITLOGS",
      description: "AuditLogs View",
    },
    {
      key: " role_privileges_view",
      name: "Role Privieleges View",
      group: "ROLEPRIVILEGES",
      description: "Role Privieleges View",
    },
  ],
};
