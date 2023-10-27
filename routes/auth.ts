import express from "express";
import {
  register,
  login,
  forgotPassword,
  resetPassword,
} from "../controllers/auth.controller";

const router = express.Router();

// Register
router.post("/register", register);

// Login
router.post("/login", login);

// Forgot Password
router.post("/forgot-password", forgotPassword);

// Forgot Password
router.post("/reset-password", resetPassword);

export default router;
