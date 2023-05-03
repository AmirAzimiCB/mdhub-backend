import User from "../models/User.js";
import Code from "../models/Code.js";
import ChildAccount from "../models/ChildAccount.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { createStripeCustomer, confirmPaymentIntent } from "../utils/utils.js";
import Stripe from "stripe";
import * as dotenv from "dotenv";
import crypto from "crypto";
import { transporter } from "../utils/utils.js";
dotenv.config();
const stripe = new Stripe(process.env.STRIPE_PRIVATE_KEY);

export const registerUser = async (req, res) => {
  try {
    const { accountType, paymentMode } = req.body.primaryUserData;
    const customer = await createStripeCustomer(req);

    if (accountType === "individual" && paymentMode === "monthly") {
      await stripe.subscriptions.create({
        customer: customer.id,
        items: [
          {
            price: "price_1MsuWeHO2OahTS06f0R7LIUC",
          },
        ],
        trial_period_days: 90,
        default_payment_method: req.body.paymentMethod,
      });
    }

    if (accountType === "individual" && paymentMode === "yearly") {
      await stripe.subscriptions.create({
        customer: customer.id,
        items: [
          {
            price: "price_1MsuY1HO2OahTS06PEoz5Dq2",
          },
        ],
        default_payment_method: req.body.paymentMethod,
      });
    }

    if (accountType === "family" && paymentMode === "monthly") {
      await stripe.subscriptions.create({
        customer: customer.id,
        items: [
          {
            price: "price_1MlB7vHO2OahTS06f5GQgKEH",
          },
        ],
        trial_period_days: 90,
        default_payment_method: req.body.paymentMethod,
      });
    }

    if (accountType === "family" && paymentMode === "yearly") {
      await stripe.subscriptions.create({
        customer: customer.id,
        items: [
          {
            price: "price_1MlBIdHO2OahTS06H9mP6k8S",
          },
        ],
        default_payment_method: req.body.paymentMethod,
      });
    }

    if (accountType === "on demand") {
      await stripe.subscriptions.create({
        customer: customer.id,
        items: [
          {
            price: "price_1MkkY2HO2OahTS06MFms2Hkr",
          },
        ],
        trial_period_days: 90,
        default_payment_method: req.body.paymentMethod,
      });
    }

    const code = await Code.findOne({ isAssigned: false });

    const newUser = new User({
      ...req.body.primaryUserData,
      password: bcrypt.hashSync(req.body.primaryUserData.password, 10),
      stripeCustomerId: customer.id,
      loginCode: code.code,
    });
    code.isAssigned = true;
    code.userId = newUser._id;
    await code.save();
    const savedUser = await newUser.save();

    // Saving Child Accounts
    if (req.body.childUsersData) {
      for (const childAccount of req.body.childUsersData.filter(Boolean)) {
        const newChildAccount = new ChildAccount({
          ...childAccount,
          password: bcrypt.hashSync(childAccount.password, 10),
          parentAccountId: savedUser._id,
        });
        const savedChildAccount = await newChildAccount.save();
        savedUser.childAccounts.push(savedChildAccount._id);
      }
      await savedUser.save();
    }

    const { password, ...others } = savedUser._doc;
    res.status(200).json({ ...others });
  } catch (err) {
    res.status(500).json(err);
  }
};

export const loginUser = async (req, res) => {
  try {
    const user = await User.findOne({
      email: req.body.email,
    }).populate("childAccounts");

    !user && res.status(401).json("User not found");

    const passwordCorrect = await bcrypt.compare(
      req.body.password,
      user.password
    );
    if (passwordCorrect) {
      const accessToken = jwt.sign(
        {
          id: user._id,
          isChildUser: user.isChildUser,
          isAdmin: user.isAdmin,
        },
        process.env.JWT_SEC,
        { expiresIn: "3d" }
      );
      user.lastLoggedIn = new Date();
      await user.save();
      const { password, createdAt, updatedAt, __v, ...others } = user._doc;
      res.status(200).json({ ...others, accessToken });
    } else {
      res.status(401).json("Incorrect Password");
    }
  } catch (err) {
    res.status(500).json(err);
  }
};

export const forgetUserPassword = async (req, res) => {
  try {
    const user = await User.findOne({
      email: req.body.email,
    }).populate("childAccounts");

    if (user) {
      // Generate a reset token and save it to the user's document in the database
      const resetToken = crypto.randomBytes(20).toString("hex");
      user.resetPasswordToken = resetToken;
      user.resetPasswordExpires = Date.now() + 43200000; // Token expires in 24 hours
      await user.save();

      // Send the password reset email to the user
      const resetLink = `${process.env.BASE_URL}/update-password/${resetToken}`;

      const mailOptions = {
        from: "asfandyar687@gmail.com",
        to: user?.email,
        subject: "Reset Password",
        html: `
          <div>
            <h2>Hello This is a email for reset password</h2>
            <p>Click on the given below URL for reset password:</p>
            <ul>
              <li>
                URL: ${resetLink}
              </li>
            </ul>
          </div>
        `,
      };
      transporter.sendMail(mailOptions, function (error, info) {
        if (error) {
          console.log("error on send email for reset password URL!", error);
        } else {
          console.log("Email sent: " + info.response);
          // do something useful
          res.status(200).json("Email Sent Successfully");
        }
      });

      res.status(200).json({
        response: "Forget password email sent on your email successfully!",
      });
    } else {
      return res
        .status(404)
        .json({ response: `${req.body.email} is not found !` });
    }
  } catch (error) {
    res.status(401).json(`${error} is not found on forget password!`);
  }
};

export const resetPassword = async (req, res) => {
  try {
    const user = await User.findOne({
      resetPasswordToken: req.body.token,
      resetPasswordExpires: { $gt: Date.now() },
    });
    if (!user) {
      return res.status(400).json({ message: "Invalid or expired token" });
    } else {
      // Hash the new password and save it to the user's document in the database

      // user.password = await hashedPassword(req.body.password);
      user.password = bcrypt.hashSync(req.body.password, 10);
      user.resetPasswordToken = null;
      user.resetPasswordExpires = null;
      await user.save();

      res.status(200).json({ response: "Password updated successfully!" });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ response: "Server Error" });
  }
};
