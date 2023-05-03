import mongoose from "mongoose";

const User = new mongoose.Schema(
  {
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    phone: { type: String, required: true, unique: true },
    isChildUser: { type: Boolean, default: false },
    gender: { type: String },
    dateOfBirth: { type: String },
    address: { type: String },
    country: { type: String },
    city: { type: String },
    region: { type: String },
    postalCode: { type: String },
    childAccounts: [
      { type: mongoose.Schema.Types.ObjectId, ref: "ChildAccount" },
    ],
    appointments: [
      { type: mongoose.Schema.Types.ObjectId, ref: "Appointment" },
    ],
    accountType: { type: String },
    paymentMode: { type: String },
    loginCode: { type: String },
    stripeCustomerId: { type: String, required: true },
    isAdmin: { type: Boolean, default: false },
    lastLoggedIn: { type: Date },
    resetPasswordToken: {
      type: String,
      default: null,
    },
    resetPasswordExpires: {
      type: String,
      default: null,
    },
  },
  { timestamps: true }
);

const UserSchema = mongoose.model("User", User);

export default UserSchema;
