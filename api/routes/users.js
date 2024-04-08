var express = require("express");
const bcrypt = require("bcrypt");
const is = require("is_js");
const jwt = require("jwt-simple");
const OTPAuth = require("otpauth");

const Users = require("../db/models/Users");
const Response = require("../lib/Response");
const CustomError = require("../lib/Error");
const Enum = require("../config/Enum");
const UserRoles = require("../db/models/UserRoles");
const RolePrivileges = require("../db/models/RolePrivileges");
const Roles = require("../db/models/Roles");
const config = require("../config");
var router = express.Router();
const auth = require("../lib/auth")();
const role_privileges = require("../config/role_privileges");
const { generateRandombase32 } = require("../lib/RandomBase32");

router.post("/register", async (req, res) => {
  let body = req.body;
  try {
    let user = await Users.findOne({});

    if (user) {
      return res.sendStatus(Enum.HTTP_CODES.NOT_FOUND);
    }

    if (!body.email)
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Validation Error!",
        "email field must be filled"
      );

    if (is.not.email(body.email))
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Validation Error!",
        "email field must be an email format"
      );

    if (!body.password)
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Validation Error!",
        "password field must be filled"
      );

    if (body.password.length < Enum.PASS_LENGTH) {
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Validation Error!",
        "password length must be greater than " + Enum.PASS_LENGTH
      );
    }

    let password = bcrypt.hashSync(body.password, bcrypt.genSaltSync(8), null);

    let createdUser = await Users.create({
      email: body.email,
      password,
      is_active: true,
      first_name: body.first_name,
      last_name: body.last_name,
      phone_number: body.phone_number,
      two_fa: body.two_fa,
      temp_secret: speakeasy.generateSecret(),
    });

    createdUser = await Users.findOne({ email: createdUser.email });

    let role = await Roles.create({
      role_name: Enum.SUPER_ADMIN,
      is_active: true,
      created_by: createdUser._id,
    });

    role = await Roles.findOne({ role_name: role.role_name });

    await UserRoles.create({
      role_id: role._id,
      user_id: createdUser._id,
    });

    let permissions = role_privileges.privileges.map((p) => p.key);

    for (let i = 0; i < permissions.length; i++) {
      let rolePrivilege = new RolePrivileges({
        role_id: role._id,
        permission: permissions[i],
        created_by: createdUser.id,
      });
      await rolePrivilege.save();
    }

    res
      .status(Enum.HTTP_CODES.CREATED)
      .json(
        Response.successResponse({ success: true }, Enum.HTTP_CODES.CREATED)
      );
  } catch (err) {
    let errorResponse = Response.errorResponse(err);
    res.status(errorResponse.code).json(errorResponse);
  }
});

router.post("/auth", async (req, res) => {
  try {
    let { email, password } = req.body;
    Users.validateFieldsBeforeAuth(email, password);
    let user = await Users.findOne({ email });
    if (!user)
      throw new CustomError(
        Enum.HTTP_CODES.UNAUTHORIZED,
        "Validation Error",
        "email or password wrong"
      );
    if (!user.validPassword(password))
      throw new CustomError(
        Enum.HTTP_CODES.UNAUTHORIZED,
        "Validation Error",
        "email or password wrong"
      );

    if (user.otp_enabled)
      return res.json(
        Response.successResponse({
          user: { _id: user._id },
          otp_enabled: user.otp_enabled,
        })
      );
    let userData = {
      _id: user._id,
      first_name: user.first_name,
      last_name: user.last_name,
      otp_enabled: user.otp_enabled,
    };
    let payload = {
      id: user._id,
      exp: parseInt(Date.now() / 1000) * config.JWT.EXPIRE_TIME,
    };
    let token = jwt.encode(payload, config.JWT.SECRET);
    res.json(Response.successResponse({ token, user: userData }));
  } catch (error) {
    let errorResponse = Response.errorResponse(error);
    res.status(errorResponse.code).json(errorResponse);
  }
});

router.post("/add", async (req, res) => {
  try {
    let body = req.body;
    if (!body.email)
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Validation Error",
        "email field must be filled"
      );
    if (is.not.email(body.email))
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Validation Error",
        "email field must be an email"
      );
    if (!body.password)
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Validation Error",
        "password field must be filled"
      );
    if (body.password.length < Enum.PASS_LENGTH)
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Validation Error",
        "password length must be greater than " + Enum.PASS_LENGTH
      );

    if (!body.roles || !Array.isArray(body.roles) || body.roles.length == 0)
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Validation Error",
        "roles field must be an array!"
      );

    let roles = await Roles.find({ _id: { $in: body.roles } });

    if (roles.length == 0)
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Validation Error",
        "roles field must be an array!"
      );

    let password = bcrypt.hashSync(body.password, bcrypt.genSaltSync(8), null);

    let user = await Users.create({
      email: body.email,
      password,
      is_active: body.is_active || true,
      first_name: body.first_name,
      last_name: body.last_name,
      phone_number: body.phone_number,
      otp_enabled: false,
      otp_verified: false,
      otp_base32: "",
      otp_auth_url: "",
    });

    for (let i = 0; i < roles.length; i++) {
      await UserRoles.create({
        role_id: roles[i]._id,
        user_id: user._id,
      });
    }

    res
      .status(Enum.HTTP_CODES.CREATED)
      .json(
        Response.successResponse(
          { success: true, _id: user._id },
          Enum.HTTP_CODES.CREATED
        )
      );
  } catch (error) {
    let errorResponse = Response.errorResponse(error);
    res.status(errorResponse.code).json(errorResponse);
  }
});

router.post("/generateOTP", async (req, res) => {
  try {
    let body = req.body;
    if (!body.user_id)
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Validation Error",
        "user_id field must be filled"
      );

    const base32_secret = generateRandombase32();

    let totp = new OTPAuth.TOTP({
      issuer: "atakan",
      label: "atakan",
      algorithm: "SHA1",
      digits: 6,
      secret: base32_secret,
    });
    let otpauth_url = totp.toString();
    await Users.updateOne(
      { _id: body.user_id },
      { otp_auth_url: otpauth_url, otp_base32: base32_secret }
    );
    res.json(Response.successResponse({ base32: base32_secret, otpauth_url }));
  } catch (error) {
    let errorResponse = Response.errorResponse(error);
    res.status(errorResponse.code).json(errorResponse);
  }
});

router.post("/verify", async (req, res) => {
  try {
    let body = req.body;

    if (!body.user_id)
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Validation Error",
        "user_id field must be filled"
      );

    if (!body.token)
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Validation Error",
        "token field must be filled"
      );

    let user = await Users.findOne({ _id: body.user_id });

    const totp = new OTPAuth.TOTP({
      issuer: "atakan",
      label: "atakan",
      algorithm: "SHA1",
      digits: 6,
      secret: user.otp_base32,
    });

    let delta = totp.validate({ token: body.token });

    if (delta === null)
      return res.status(Enum.HTTP_CODES.UNAUTHORIZED).json({ success: false });

    let updatedUser = await Users.updateOne(
      { _id: user._id },
      { otp_enabled: true, otp_verified: true }
    );
    return res.json(
      Response.successResponse({
        otp_verified: true,
        user: {
          id: updatedUser.id,
          name: updatedUser.name,
          email: updatedUser.email,
          otp_enabled: updatedUser.otp_enabled,
        },
      })
    );
  } catch (error) {
    let errorResponse = Response.errorResponse(error);
    res.status(errorResponse.code).json(errorResponse);
  }
});

router.post("/validate", async (req, res) => {
  try {
    let body = req.body;
    if (!body.user_id)
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Validation Error",
        "user_id field must be filled"
      );
    if (!body.token)
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Validation Error",
        "token field must be filled"
      );
    let user = await Users.findOne({ _id: body.user_id });
    const totp = new OTPAuth.TOTP({
      issuer: "atakan",
      label: "atakan",
      algorithm: "SHA1",
      digits: 6,
      secret: user.otp_base32,
    });
    let delta = totp.validate({ token: body.token });
    if (delta === null)
      return res.status(Enum.HTTP_CODES.UNAUTHORIZED).json({ success: false });

    let userData = {
      _id: user._id,
      first_name: user.first_name,
      last_name: user.last_name,
      otp_enabled: user.otp_enabled,
    };
    let payload = {
      id: user._id,
      exp: parseInt(Date.now() / 1000) * config.JWT.EXPIRE_TIME,
    };
    let token = jwt.encode(payload, config.JWT.SECRET);
    res.json(Response.successResponse({ token, user: userData }));
  } catch (error) {
    let errorResponse = Response.errorResponse(error);
    res.status(errorResponse.code).json(errorResponse);
  }
});

router.post("/disableOTP", async (req, res) => {
  try {
    let body = req.body;
    if (!body.user_id)
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Validation Error",
        "user_id field must be filled"
      );
    let user = await Users.findOne({ _id: body.user_id });
    await Users.updateOne(
      { _id: user._id },
      { otp_enabled: false, otp_verified: false }
    );
    res.json(Response.successResponse({ success: true }));
  } catch (error) {
    let errorResponse = Response.errorResponse(error);
    res.status(errorResponse.code).json(errorResponse);
  }
});

router.all("*", auth.authenticate(), (req, res, next) => {
  next();
});

router.get("/", auth.checkRoles("user_view"), async (req, res) => {
  try {
    let users = await Users.find({});
    res.json(Response.successResponse(users));
  } catch (error) {
    let errorResponse = Response.errorResponse(error);
    res.status(errorResponse.code).json(errorResponse);
  }
});

router.post("/update", auth.checkRoles("user_update"), async (req, res) => {
  try {
    let body = req.body;
    let updates = {};
    if (!body._id)
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Validation Error",
        "_id field must be filled!"
      );
    if (body.password && body.password.length < Enum.PASS_LENGTH) {
      updates.password = bcrypt.hashSync(
        body.password,
        bcrypt.genSaltSync(8),
        null
      );
    }
    if (typeof body.is_active === "boolean") updates.is_active = body.is_active;
    if (body.first_name) updates.first_name = body.first_name;
    if (body.last_name) updates.last_name = body.last_name;
    if (body.phone_number) updates.phone_number = body.phone_number;
    if (Array.isArray(body.roles) && body.roles.length > 0) {
      let userRoles = await UserRoles.find({ user_id: body._id });
      let removedRoles = userRoles.filter(
        (role) => !body.roles.includes(role.role_id.toString())
      );
      let newRoles = body.roles.filter(
        (role) => !userRoles.map((r) => r.role_id).includes(role)
      );
      if (removedRoles.length > 0) {
        await UserRoles.deleteMany({
          _id: { $in: removedRoles.map((role) => role._id.toString()) },
        });
      }
      if (newRoles.length > 0) {
        for (let i = 0; i < newRoles.length; i++) {
          let userRole = new UserRoles({
            role_id: newRoles[i],
            user_id: body._id,
          });
          await userRole.save();
        }
      }
    }

    await Users.updateOne({ _id: body._id }, updates);

    res.json(Response.successResponse({ success: true }));
  } catch (error) {
    let errorResponse = Response.errorResponse(error);
    res.status(errorResponse.code).json(errorResponse);
  }
});

router.post("/delete", auth.checkRoles("user_delete"), async (req, res) => {
  try {
    let body = req.body;
    if (!body._id)
      throw new CustomError(
        Enum.HTTP_CODES.BAD_REQUEST,
        "Validation Error!",
        "_id field must be filled"
      );

    await Users.deleteOne({ _id: body._id });
    await UserRoles.deleteMany({ user_id: body._id });
    res.json(Response.successResponse({ success: true }));
  } catch (error) {
    let errorResponse = Response.errorResponse(error);
    res.status(errorResponse.code).json(errorResponse);
  }
});

module.exports = router;
