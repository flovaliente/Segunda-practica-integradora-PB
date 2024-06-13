import { Router } from 'express';
import passport from 'passport';
import { generateToken, authToken } from '../utils/utils.js';
import { passportCall } from '../utils/authUtil.js';
import { authorization } from '../middlewares/auth.js';
import { isValidPassword } from '../utils/functionsUtils.js';

import UserManagerDB from '../dao/UserManagerDB.js';
import CartManagerDB from '../dao/CartManagerDB.js';

const router = Router();
const userManager = new UserManagerDB();
const cartManager = new CartManagerDB();

router.post('/register', passport.authenticate("register", { failureRedirect: "/api/session/failRegister" }), async (req, res) =>{
    try {
        const user = req.body;
        const result = await userManager.registerUser(user);
        const cart = await cartManager.createCart();
        await userManager.createUserCart(result._id, cart._id);
        res.redirect('/login');
    } catch (error) {
        res.redirect('/register');
    }
    
});

router.get('/failRegister', (req, res) =>{
    res.status(400).send({
        status: "error",
        message: "Filed register"
    });
});

router.post("/login", async (req, res) =>{
   const { email, password } = req.body; 
   try {
        req.session.failLogin = false;
        
        const user = await userManager.findUserByEmail(email)//Busco el usuario con email: email
        if(!user || !isValidPassword(user, password)){
            //console.log('Usuario no encontrado o contraseña incorrecta');
            req.session.failLogin = true;
            return res.redirect("/login");
        }

        req.session.user = user;
        const accessToken = generateToken(user);
        console.log(accessToken);
        res.cookie('accessToken', accessToken, { maxAge: 60*60*1000, httpOnly: true });
        //console.log('Login exitoso!');
        return res.redirect("/products");
        //return res.json({ message: 'Logged in', token: accessToken });
    } catch (error) {
        //console.log('Error durante el login. Error: ', error.message);
        req.session.failLogin = true;
        return res.redirect("/login");
    }
    
});

router.get('/failLogin', (req, res) =>{
    res.status(400).send({
        status: "error",
        message: "Filed login"
    });
});

router.get('/logout', async (req, res) =>{
    req.session.destroy( error =>{
        res.clearCookie("accessToken");
        res.redirect("/login");
    });
});

/*router.get('/current', authToken, (req, res) =>{
    res.send({
        status: 'success',
        user: req.user
    });
});*/

router.get('/current', passportCall('jwt'), authorization('User'), (req, res) =>{
    res.send({
        status: 'success',
        user: req.user
    });
});

export default router;