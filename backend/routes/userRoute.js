import express from 'express';
import { 
    loginUser,
    registerUser,
    adminLogin,
    getAllUsers,
    getUserById,
    updateUser,
    deleteUser,
    verifyToken
} from '../controllers/userController.js';

const userRouter = express.Router();


userRouter.post('/register', registerUser);
userRouter.post('/login', loginUser);
userRouter.post('/admin', adminLogin);
userRouter.get('/verify', verifyToken, (req, res) => {
    res.json({
        success: true,
        message: 'Token verified successfully.',
        user: req.user,
    });
});


userRouter.get('/', getAllUsers);
userRouter.get('/:id', getUserById);
userRouter.put('/:id', updateUser);
userRouter.delete('/:id', deleteUser);

export default userRouter;
