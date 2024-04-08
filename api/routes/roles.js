const express = require("express");
const router = express.Router();
const Roles = require("../db/models/Roles");
const Response = require("../lib/Response");
const CustomError = require("../lib/Error");
const Enum = require("../config/Enum");
const role_privileges = require("../config/role_privileges");
const RolePrivileges = require("../db/models/RolePrivileges");
const auth = require("../lib/auth")();

router.all("*", auth.authenticate(), (req, res, next) => {
  next();
});

router.get("/", auth.checkRoles("role_view"), async (req, res, next) => {
  try {
    let roles = await Roles.find({});
    res.json(Response.successResponse(roles));
  } catch (error) {
    let errorResponse = Response.errorResponse(error);
    res.status(error.code).json(errorResponse);
  }
});

router.post("/add", auth.checkRoles("role_add"), async (req, res) => {
  let body = req.body;
  try {
    if (!body.role_name)
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Validation Error",
        "Role name field must be filled"
      );

    if (
      !body.permissions ||
      !Array.isArray(body.permissions) ||
      body.permissions.length == 0
    ) {
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Validation Error",
        "Permission field must be filled and array"
      );
    }

    let role = new Roles({
      role_name: body.role_name,
      is_active: body.is_active,
      created_by: req.user?.id,
    });

    await role.save();

    for (let i = 0; i < body.permissions.length; i++) {
      let rolePrivilege = new RolePrivileges({
        role_id: role._id,
        permission: body.permissions[i],
        created_by: req.user?.id,
      });

      console.log("rolePrivilege", rolePrivilege);

      await rolePrivilege.save();
    }

    res.json(Response.successResponse({ success: true }));
  } catch (error) {
    let errorResponse = Response.errorResponse(error);
    res.status(errorResponse.code).json(errorResponse);
  }
});

router.post("/update", auth.checkRoles("role_update"), async (req, res) => {
  let body = req.body;
  try {
    if (!body._id) {
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Validation Error",
        "_id field must be filled"
      );
    }

    let updates = {};

    if (body.role_name) updates.role_name = body.role_name;
    if (typeof body.is_active === "boolean") updates.is_active = body.is_active;

    if (
      body.permissions &&
      Array.isArray(body.permissions) &&
      body.permissions.length > 0
    ) {
      let rolePrivileges = await RolePrivileges.find({ role_id: body._id });
      let removedPermissions = rolePrivileges.filter(
        (privilege) => !body.permissions.includes(privilege.permission)
      );
      let newPermissions = body.permissions.filter(
        (privilege) =>
          !rolePrivileges.map((p) => p.permission).includes(privilege)
      );
      if (removedPermissions.length > 0) {
        await RolePrivileges.deleteMany({
          _id: {
            $in: removedPermissions.map((permission) => permission._id),
          },
        });
      }
      if (newPermissions.length > 0) {
        for (let i = 0; i < newPermissions.length; i++) {
          let rolePrivilege = new RolePrivileges({
            role_id: body._id,
            permission: newPermissions[i],
            created_by: req.user?.id,
          });
          await rolePrivilege.save();
        }
      }
    }
    await Roles.updateOne({ _id: body._id }, updates);
    res.json(Response.successResponse({ success: true }));
  } catch (error) {
    let errorResponse = Response.errorResponse(error);
    res.status(errorResponse.code).json(errorResponse);
  }
});

router.post("/delete", auth.checkRoles("role_delete"), async (req, res) => {
  let body = req.body;
  try {
    if (!body._id)
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Validation Error",
        "_id field must be filled"
      );
    await Roles.deleteOne({ _id: body._id });
    res.json(Response.successResponse({ success: true }));
  } catch (error) {
    let errorResponse = Response.errorResponse(error);
    res.status(errorResponse.code).json(errorResponse);
  }
});

router.get(
  "/role_privileges",
  auth.checkRoles("role_privileges_view"),
  async (req, res) => {
    res.json(role_privileges);
  }
);

module.exports = router;
