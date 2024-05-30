import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import User from "../models/User.js";

dotenv.config();

export const signup = async (req, res, next) => {
  try {
    const { user } = req.body;
    const salt = 10;
    user["password"] = await bcrypt.hash(user.password, salt);
    const newUser = await User.create(user);
    res.status(201).send({ success: true, message: "user created" });
  } catch (error) {
    return next(error);
  }
};

export const login = async (req, res, next) => {
  try {
    const { user } = req.body;
    const myUser = await User.findOne({ email: user.email });
    if (myUser && (await bcrypt.compare(user.password, myUser.password))) {
      const payload = {
        id: myUser._id,
        name: myUser.name,
        email: myUser.email,
      };
      const token = jwt.sign(payload, process.env.JWT_SECRET_KEY);
      return res
        .status(200)
        .send({ success: true, message: "Login successfull", token: token });
    }
    return res
      .status(400)
      .send({ success: false, message: "Wrong email or password" });
  } catch (error) {
    return next(error);
  }
};
