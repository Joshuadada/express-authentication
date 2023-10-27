import { NextFunction, Request, Response } from "express";
import connection from "../db_config";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import crypto from "crypto";
import ejs from "ejs";

// Create token function
const maxAge = 3 * 24 * 60 * 60; //3 days
const createToken = (userEmail: string) => {
  return jwt.sign({ userEmail }, "authentication", {
    expiresIn: maxAge,
  });
};

// Create a Nodemailer transporter with your email service configuration
const transporter = nodemailer.createTransport({
  service: "Gmail", // e.g., 'Gmail', 'Outlook', etc.
  auth: {
    user: "jdbabatunde98@gmail.com",
    pass: "nwdxkwupvxpfddlc",
  },
});

// Generate token function
const generateToken = () => {
  return crypto.randomBytes(20).toString("hex");
};

// Registration Function
export const register = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { userName, userEmail, userPassword } = req.body;

    // check if required fields are empty
    if (!userName || !userEmail || !userPassword) {
      if (!userName) {
        return res.status(400).json({
          status: false,
          message: "Name cannot be empty",
        });
      }
      if (!userEmail) {
        return res.status(400).json({
          status: false,
          message: "Email cannot be empty",
        });
      }
      if (!userPassword) {
        return res.status(400).json({
          status: false,
          message: "Password cannot be empty",
        });
      }
    }

    // check if user already exist
    const userExistQuery = `SELECT * FROM user WHERE user_email = '${userEmail}'`;
    connection.query(userExistQuery, (err, result) => {
      if (result.length !== 0) {
        return res.status(400).json({
          status: false,
          message: "User Already exist",
        });
      }
    });

    // encrypt password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(userPassword, saltRounds);

    //register user
    const registerQuery =
      "INSERT INTO user (user_name, user_email, user_password) VALUES (?, ?, ?)";
    const values = [userName, userEmail, hashedPassword];

    connection.query(registerQuery, values, (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).json({
          status: false,
          message: "User registration failed",
        });
      }

      const token = createToken(userEmail);
      res.cookie("jwt", token, { httpOnly: true, maxAge: maxAge * 1000 });
      return res.status(201).json({
        status: true,
        message: "User created successfully",
        token,
        data: {
          id: result.insertId,
          userName,
          userEmail,
        },
      });
    });
  } catch (error) {
    console.error(error);
    return res
      .status(500)
      .json({ status: false, message: "User registration failed" });
  }
};

// Login Function
export const login = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { userEmail, userPassword } = req.body;

    // Check if required fields are empty
    if (!userEmail || !userPassword) {
      return res.status(400).json({
        status: false,
        message: "Email and password are required",
      });
    }

    // Check if the user exists
    const userExistQuery = "SELECT * FROM user WHERE user_email = ? LIMIT 1";
    connection.query(userExistQuery, [userEmail], async (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).json({
          status: false,
          message: "Database error",
        });
      }

      if (result.length === 0) {
        return res.status(400).json({
          status: false,
          message: "Invalid login credentials",
        });
      }

      const userData = result[0];
      const hashedPassword = userData?.user_password;

      // Verify the password
      const passwordMatch = await bcrypt.compare(userPassword, hashedPassword);
      if (!passwordMatch) {
        return res.status(400).json({
          status: false,
          message: "Invalid login credentials",
        });
      }

      const token = createToken(userEmail);
      res.cookie("jwt", token, { httpOnly: true, maxAge: maxAge * 1000 });

      return res.status(200).json({
        status: true,
        message: "User logged in successfully",
        token,
        data: {
          id: userData?.user_id,
          userName: userData?.user_name,
          userEmail: userData?.user_email,
        },
      });
    });
  } catch (error) {
    console.error(error);
    return res
      .status(500)
      .json({ status: false, message: "User login failed" });
  }
};

// Forgot Password Function
export const forgotPassword = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { userEmail } = req.body;

    // Check if required fields are empty
    if (!userEmail) {
      return res.status(400).json({
        status: false,
        message: "Email is required",
      });
    }

    const token = generateToken();
    const expirationTime = new Date();
    expirationTime.setHours(expirationTime.getHours() + 1); // Token expires in 1 hour

    const updateTokenQuery =
      "UPDATE user SET reset_password_token = ?, reset_password_expires = ? WHERE user_email = ?";
    connection.query(updateTokenQuery, [token, expirationTime, userEmail]);

    const resetLink = `http://yourapp.com/reset-password?token=${token}`;

    // Render the email template with resetLink
    ejs.renderFile("views/reset-password.ejs", { resetLink }, (err, data) => {
      if (err) {
        console.error(err);
        return res.status(500).json({
          status: false,
          message: "Email template rendering failed.",
        });
      }

      const mailOptions = {
        from: "jdbabatunde98@gmail.com",
        to: "jaisofchristnation@gmail.com",
        subject: "Password Reset",
        text: `To reset your password, click the following link: ${resetLink}`,
      };

      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error(error);
          res
            .status(500)
            .json({ status: false, message: "Failed to send email" });
        } else {
          console.log("Email sent: " + info.response);
          return res.status(200).json({
            status: true,
            message: "Password resend link sent, kindly check your email",
          });
        }
      });
    });
  } catch (error) {
    console.error(error);
    res
      .status(500)
      .json({ status: false, message: "Password reset request failed." });
  }
};

// Reset Password Function
export const resetPassword = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const { token, newPassword } = req.body;

  try {
    // Verify token and check if it's not expired
    const currentTime = new Date();
    connection.query(
      "SELECT * FROM users WHERE reset_password_token = ? AND reset_password_expires > ?",
      [token, currentTime],
      async (err, result) => {
        if (err) {
          console.error(err);
          return res.status(500).json({
            status: false,
            message: "Database error",
          });
        }

        if (result.length === 0) {
          return res
            .status(400)
            .json({ status: false, message: "Invalid or expired token." });
        }

        // Update the password
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        connection.query(
          "UPDATE users SET password = ?, reset_password_token = NULL, reset_password_expires = NULL WHERE email = ?",
          [hashedPassword, result[0].email]
        );

        res
          .status(200)
          .json({ status: true, message: "Password reset successful." });
      }
    );
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: false, message: "Password reset failed." });
  }
};
