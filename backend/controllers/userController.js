import validator from "validator";
import bcrypt from "bcrypt";
import jwt from 'jsonwebtoken';
import userModel from "../models/userModel.js";

//token with user info (id, name, email)
const createToken = (user) => {
    return jwt.sign(
        { id: user._id, name: user.name, email: user.email }, 
        process.env.JWT_SECRET,
        { expiresIn: '15m' }  // Set expiry for token 
    );
};

//  user login
const loginUser = async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await userModel.findOne({ email });

        if (!user) {
            return res.json({ success: false, message: "User doesn't exist" });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (isMatch) {
            const token = createToken(user);
            res.json({ success: true, token });
        } else {
            res.json({ success: false, message: 'Invalid credentials' });
        }

    } catch (error) {
        console.log(error);
        res.json({ success: false, message: error.message });
    }
};

//  user register
const registerUser = async (req, res) => {
    try {
        const { name, email, password } = req.body;

        const exists = await userModel.findOne({ email });
        if (exists) {
            return res.json({ success: false, message: "User already exists" });
        }

        if (!validator.isEmail(email)) {
            return res.json({ success: false, message: "Please enter a valid email" });
        }
        if (password.length < 8) {
            return res.json({ success: false, message: "Please enter a strong password" });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new userModel({
            name,
            email,
            password: hashedPassword
        });

        const user = await newUser.save();

        const token = createToken(user);

        res.json({ success: true, token });

    } catch (error) {
        console.log(error);
        res.json({ success: false, message: error.message });
    }
};

//  admin login
const adminLogin = async (req, res) => {
    try {
        const { email, password } = req.body;

        if (email === process.env.ADMIN_EMAIL && password === process.env.ADMIN_PASSWORD) {
            const token = jwt.sign(email + password, process.env.JWT_SECRET);
            res.json({ success: true, token });
        } else {
            res.json({ success: false, message: "Invalid credentials" });
        }

    } catch (error) {
        console.log(error);
        res.json({ success: false, message: error.message });
    }
};


//  fetch all users
const getAllUsers = async (req, res) => {
    try {
        const users = await userModel.find({}, '-password'); // Exclude password field
        res.json({ success: true, users });
    } catch (error) {
        console.log(error);
        res.json({ success: false, message: error.message });
    }
};

// fetch a single user by ID
const getUserById = async (req, res) => {
    try {
        const { id } = req.params;
        const user = await userModel.findById(id, '-password'); // Exclude password field

        if (!user) {
            return res.json({ success: false, message: "User not found" });
        }

        res.json({ success: true, user });
    } catch (error) {
        console.log(error);
        res.json({ success: false, message: error.message });
    }
};

//  update user data
const updateUser = async (req, res) => {
    try {
        const { id } = req.params;
        const { name, email } = req.body;

        // Validate email format 
        if (email && !validator.isEmail(email)) {
            return res.json({ success: false, message: "Please enter a valid email" });
        }

        const updatedUser = await userModel.findByIdAndUpdate(
            id,
            { name, email },
            { new: true, runValidators: true, select: '-password' } // Return updated user 
        );

        if (!updatedUser) {
            return res.json({ success: false, message: "User not found" });
        }

        res.json({ success: true, user: updatedUser });
    } catch (error) {
        console.log(error);
        res.json({ success: false, message: error.message });
    }
};

//  delete user route
const deleteUser = async (req, res) => {
    try {
        const { id } = req.params;

        const deletedUser = await userModel.findByIdAndDelete(id);

        if (!deletedUser) {
            return res.json({ success: false, message: "User not found" });
        }

        res.json({ success: true, message: "User deleted successfully" });
    } catch (error) {
        console.log(error);
        res.json({ success: false, message: error.message });
    }
};

//   token verification
const verifyToken = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ success: false, message: 'Access Denied. No token provided.' });
    }

    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        req.user = verified;
        next();
    } catch (error) {
        console.log(error);
        res.status(400).json({ success: false, message: 'Invalid token.' });
    }
};


export {
    loginUser,
    registerUser,
    adminLogin,
    getAllUsers,
    getUserById,
    updateUser,
    deleteUser,
    verifyToken
};
