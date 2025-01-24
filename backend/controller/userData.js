const jwt = require("jsonwebtoken");
const { UserData, UserLogin } = require("../model/userData");
const bcrypt = require("bcrypt");
const CryptoJS = require("crypto-js");
require("dotenv").config(); // Add this line to load environment variables

// Encryption key from environment variables
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;

// Encryption/decryption helper functions
const encryptData = (text) => {
  return CryptoJS.AES.encrypt(text, ENCRYPTION_KEY).toString();
};

const decryptData = (encryptedText) => {
  const bytes = CryptoJS.AES.decrypt(encryptedText, ENCRYPTION_KEY);
  return bytes.toString(CryptoJS.enc.Utf8);
};

// Helper function to capitalize words
const capitalizeWords = (input) => {
  return input.replace(/\b\w/g, (char) => char.toUpperCase());
};

// Get all user data by ID
exports.getAllUserData = async (req, res) => {
  try {
    const userId = req.params.id;
    const userData = await UserData.find({ userLogin: userId });
    if (!userData) {
      return res.status(404).send({ message: "User not found" });
    }

    // Decrypt passwords before sending response
    const decryptedData = userData.map((data) => ({
      ...data.toObject(),
      password: decryptData(data.password),
    }));

    res.status(200).json(decryptedData);
  } catch (error) {
    console.error("Error in getUserDataById:", error);
    return res.status(500).send({ message: "Error", error: error.message });
  }
};

// Create new user data
exports.createUserData = async (req, res) => {
  try {
    const { appName, userName, password, loginEmail } = req.body;
    const capitalizedAppName = capitalizeWords(appName.trim());

    // Encrypt the password
    const encryptedPassword = encryptData(password);

    const existingUserLogin = await UserLogin.findOne({ loginEmail });
    if (existingUserLogin) {
      const existingUser = await UserData.findOne({
        appName: capitalizedAppName,
        userLogin: existingUserLogin._id,
      });
      if (existingUser) {
        return res.status(400).send({ message: "Data already exists" });
      } else {
        const userData = new UserData({
          appName: capitalizedAppName,
          userName,
          password: encryptedPassword,
          userLogin: existingUserLogin._id,
        });
        await userData.save();

        // Decrypt password for response
        const responseData = userData.toObject();
        responseData.password = decryptData(responseData.password);

        return res.status(201).send({
          message: "User created successfully",
          data: responseData,
        });
      }
    } else {
      const userLogin = new UserLogin({ loginEmail });
      await userLogin.save();
      const userData = new UserData({
        appName: capitalizedAppName,
        userName,
        password: encryptedPassword,
        userLogin: userLogin._id,
      });
      await userData.save();

      // Decrypt password for response
      const responseData = userData.toObject();
      responseData.password = decryptData(responseData.password);

      return res.status(201).send({
        message: "User created successfully",
        data: responseData,
      });
    }
  } catch (error) {
    console.error("Error in createUserData:", error);
    return res.status(500).send({ message: "Error", error: error.message });
  }
};

// Update user data
exports.updateUserData = async (req, res) => {
  const id = req.params.id;
  const reqBody = req.body;

  try {
    const existingUser = await UserData.findById({ _id: id }).populate(
      "userLogin"
    );
    if (!existingUser) {
      return res.status(404).send({ message: "User not found" });
    }
    if (existingUser.userLogin.loginEmail !== reqBody.loginEmail) {
      return res.status(401).send({ message: "Unauthorized access" });
    }

    // Encrypt password if it's being updated
    if (reqBody.password) {
      reqBody.password = encryptData(reqBody.password);
    }

    const updatedUserData = await UserData.findByIdAndUpdate(id, reqBody, {
      new: true,
      runValidators: true,
    });

    // Decrypt password before sending response
    const responseData = updatedUserData.toObject();
    responseData.password = decryptData(responseData.password);

    return res.status(202).send({
      message: "Data has been updated",
      data: responseData,
    });
  } catch (error) {
    console.error("Error occurred during update:", error);
    return res
      .status(500)
      .send({ message: "Error updating data", error: error });
  }
};

// Login user
exports.login = async (req, res) => {
  const { loginEmail, loginPassword } = req.body;
  try {
    const user = await UserLogin.findOne({ loginEmail: loginEmail });
    if (!user) {
      return res.status(404).send({ message: "User not found" });
    }
    const isMatched = await bcrypt.compare(loginPassword, user.loginPassword);
    if (!isMatched) {
      return res.status(401).send({ message: "Invalid Password" });
    }
    const token = jwt.sign(
      {
        _id: user._id,
        loginEmail: user.loginEmail,
        name: user.name,
      },
      "yourjwtsectrate",
      { expiresIn: "10h" }
    ); // Changed to 10 hours from 10

    return res.status(200).send({
      message: "User LoggedIn",
      data: user,
      token: token,
    });
  } catch (error) {
    console.error("Error occurred during login:", error);
    return res.status(500).send({ message: "Error logging in", error: error });
  }
};

// Signup new user
exports.signup = async (req, res) => {
  const { name, loginEmail, loginPassword } = req.body;
  try {
    const existingUser = await UserLogin.findOne({ loginEmail: loginEmail });
    if (existingUser) {
      return res.status(400).send({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(loginPassword, 10);

    const newUser = new UserLogin({
      name: name,
      loginEmail: loginEmail.toLowerCase(),
      loginPassword: hashedPassword,
    });

    await newUser.save();
    return res.status(201).send({ message: "User Created", data: newUser });
  } catch (error) {
    console.error("Error occurred during signup:", error);
    return res
      .status(500)
      .send({ message: "Error creating user", error: error });
  }
};

// Delete user data
exports.deleteUserData = async (req, res) => {
  const id = req.params.id;
  try {
    const existingUser = await UserData.findById(id);
    if (!existingUser) {
      return res.status(404).send({ message: "User not found" });
    }
    await UserData.findByIdAndDelete(id);
    res.status(202).send({ message: "Data has been deleted" });
  } catch (error) {
    return res.status(500).send({ message: "error", error: error });
  }
};

// Update password
exports.updatePassword = async (req, res) => {
  try {
    const loginEmail = req.params.id;
    const { loginPassword } = req.body;
    const existingUser = await UserLogin.findOne({ loginEmail: loginEmail });

    if (!existingUser) {
      return res.status(404).send({ message: "User not found" });
    }

    const hashedPassword = await bcrypt.hash(loginPassword, 10);
    existingUser.loginPassword = hashedPassword;

    await existingUser.save();
    res
      .status(202)
      .send({ message: "Data has been updated", data: existingUser });
  } catch (error) {
    return res.status(500).send({ message: "error", error: error });
  }
};
