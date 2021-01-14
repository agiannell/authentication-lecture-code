const bcrypt = require('bcryptjs');

module.exports = {
    register: async(req, res) => {
        // 1. What does this function need to work properly?
        const { email, password } = req.body,
              db = req.app.get('db');

        // 2. Check if the user already has an account w/ the check_user query
        const foundUser = await db.check_user({email});
        if(foundUser[0]) {
            return res.status(400).send('Email already in use');
        }

        // 3. Hash and salt the user's password, insert their info into the db
        let salt = bcrypt.genSaltSync(10)
        const hash = bcrypt.hashSync(password, salt);

        const newUser = await db.register_user({email, hash});

        // 4. Place the user on a session, and send their info client-side
        req.session.user = newUser[0];
        res.status(201).send(req.session.user)
    },
    login: async(req, res) => {
        // 1. What does the function need to work properly
        const { email, password } = req.body,
              db = req.app.get('db');

        // 2. Check to see if the email is in the db
        const foundUser = await db.check_user({email});
        if(!foundUser[0]) {
            return res.status(404).send('Email not found')
        }

        // 3. Make sure the password matches the hashed value
        const authenticated = bcrypt.compareSync(password, foundUser[0].password);
        if(!authenticated) {
            return res.status(401).send('Password is incorrect')
        }

        delete foundUser[0].password;

        // 4. Place the user on a session, and send the info client-side
        req.session.user = foundUser[0];
        res.status(202).send(req.session.user);
    },
    logout: (req, res) => {
        // 1. Clear the user session
        req.session.destroy();
        // 2. Send back a status code
        res.sendStatus(200);
    }
}