import express from "express";
import {
  registerUser,
  loginUser,
  forgetUserPassword,
  resetPassword,
} from "../controllers/authController.js";

const router = express.Router();

//REGISTER
router.route("/register").post(registerUser);

// LOGIN
router.route("/login").post(loginUser);

// Reset Password email send on user Email
router.route("/resetPassword").post(forgetUserPassword);

// Update Password
router.route("/updatePassword").post(resetPassword);

export default router;
