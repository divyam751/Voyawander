const { User } = require("../models/user.model");
const bcrypt = require("bcrypt");
const { ApiResponse } = require("../utils/ApiResponse");
const { SECRET_KEY } = require("../constants");
const crypto = require("crypto");
// const { OTP } = require("../models/otp.model");
const { sendEmail } = require("../utils/EmailSender");
const jwt = require("jsonwebtoken");
const { generateOTP } = require("../utils/OtpGenerator");

// Register a new user
const register = async (req, res) => {
  try {
    const { fullname, email, password } = req.body;

    if (!fullname || !email || !password) {
      return ApiResponse.error(res, [], 400, "All fields are required");
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return ApiResponse.error(res, [], 409, "Email already in use");
    }

    // Send OTP to User's Email

    const otp = await generateOTP(email);

    const to = email;
    const subject = "Voyawander email verification code";
    const text = `Your OTP is ${otp}`;

    await sendEmail(to, subject, text);

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      fullname,
      email,
      password: hashedPassword,
    });

    await user.save();

    ApiResponse.success(
      res,
      { userId: user._id },
      201,
      "User registered successfully"
    );
  } catch (err) {
    console.error("Error in register:", err);
    ApiResponse.error(res, [err.message], 500, "Failed to register user");
  }
};

// User login
const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return ApiResponse.error(res, [], 400, "Email and password are required");
    }

    const user = await User.findOne({ email });
    if (!user) {
      return ApiResponse.error(res, [], 404, "User not found");
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return ApiResponse.error(res, [], 401, "Invalid credentials");
    }

    const token = jwt.sign({ userId: user._id }, SECRET_KEY, {
      expiresIn: "1h",
    });

    ApiResponse.success(res, { token }, 200, "Login successful");
  } catch (err) {
    console.error("Error in login:", err);
    ApiResponse.error(res, [err.message], 500, "Failed to log in");
  }
};

// Update password
const updatePassword = async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;

    // Validate inputs
    if (!oldPassword || !newPassword) {
      return ApiResponse.error(
        res,
        [],
        400,
        "Old and new passwords are required"
      );
    }

    const userId = req.user.userId; // userId is now in req.user from the authenticate middleware

    console.log({ userId });

    // Fetch user by ID
    const user = await User.findById(userId);
    if (!user) {
      return ApiResponse.error(res, [], 404, "User not found");
    }

    // Verify the old password
    const isOldPasswordValid = await bcrypt.compare(oldPassword, user.password);
    if (!isOldPasswordValid) {
      return ApiResponse.error(res, [], 401, "Old password is incorrect");
    }

    // Hash and update the new password
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedNewPassword;

    await user.save();

    ApiResponse.success(res, {}, 200, "Password updated successfully");
  } catch (err) {
    console.error("Error in updatePassword:", err);
    ApiResponse.error(res, [err.message], 500, "Failed to update password");
  }
};

// Forget Password (Send OTP)
const forgetPassword = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return ApiResponse.error(res, [], 400, "Email is required");
    }

    const user = await User.findOne({ email });
    if (!user) {
      return ApiResponse.error(res, [], 404, "User not found");
    }

    // Generate a 6-digit OTP
    const otp = crypto.randomInt(100000, 999999).toString();

    // Set expiration time (10 minutes from now)
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    // Save OTP to the database
    await OTP.create({ email, otp, expiresAt });

    // Send OTP via email
    const emailSent = await sendEmail(
      email,
      "Password Reset OTP",
      `Your OTP is: ${otp}`
    );
    if (!emailSent) {
      return ApiResponse.error(
        res,
        [],
        500,
        "Failed to send OTP. Please try again."
      );
    }

    ApiResponse.success(res, {}, 200, "OTP sent successfully");
  } catch (err) {
    console.error("Error in forgetPassword:", err);
    ApiResponse.error(
      res,
      [err.message],
      500,
      "Failed to process forget password"
    );
  }
};

// Reset Password
const resetPassword = async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;

    // Validate inputs
    if (!email || !otp || !newPassword) {
      return ApiResponse.error(
        res,
        [],
        400,
        "Email, OTP, and new password are required"
      );
    }

    // Fetch OTP entry from the database
    const otpEntry = await OTP.findOne({ email, otp });
    if (!otpEntry) {
      return ApiResponse.error(res, [], 400, "Invalid OTP");
    }

    // Check if OTP has expired
    if (new Date() > otpEntry.expiresAt) {
      await OTP.deleteOne({ _id: otpEntry._id }); // Clean up expired OTP
      return ApiResponse.error(res, [], 400, "OTP has expired");
    }

    // Fetch the user
    const user = await User.findOne({ email });
    if (!user) {
      return ApiResponse.error(res, [], 404, "User not found");
    }

    // Hash and update the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    // Remove OTP from the database
    await OTP.deleteOne({ _id: otpEntry._id });

    ApiResponse.success(res, {}, 200, "Password reset successfully");
  } catch (err) {
    console.error("Error in resetPassword:", err);
    ApiResponse.error(res, [err.message], 500, "Failed to reset password");
  }
};

module.exports = {
  register,
  login,
  updatePassword,
  forgetPassword,
  resetPassword,
};
