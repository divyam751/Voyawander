// booking.route.js
const express = require("express");
const {
  // addBooking,
  // getAllBookings,
  // getTotalAmount,
  createBooking,
  getTotalAmount,
  saveBookingDetails,
} = require("../controllers/booking.controller");
const { AuthMiddleware } = require("../middlewares/auth.middleware");

const bookingRouter = express.Router();

// Route to add a new booking
// bookingRouter.post("/add", addBooking);
bookingRouter.post("/create", createBooking);
bookingRouter.post("/total-amount", getTotalAmount);
bookingRouter.post(
  "/save-booking",
  AuthMiddleware.authenticate,
  saveBookingDetails
);

// Route to get all bookings
// bookingRouter.get("/all", getAllBookings);
// bookingRouter.get("/totalamount", getTotalAmount);

module.exports = { bookingRouter };
