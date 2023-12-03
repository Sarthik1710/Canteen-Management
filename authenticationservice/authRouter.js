const router = require("express").Router();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const verifyJWT = require("./auth");
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('database.db');

router.post("/signup", async (req, res) => {
  const name = req.body.name;
  const email = req.body.email;
  const password = req.body.password;
  const hashedPassword = await bcrypt.hash(password, 10);

  // Insert a new user
  const insertUser = (name, email, password) => {
    const query = 'INSERT INTO users (name, email, password) VALUES (?, ?, ?)';
    db.run(query, [name, email, password], (err) => {
      if (err) {
        console.error(err.message);
      } else {
        console.log('User inserted successfully');
      }
    });
  };

  insertUser(name, email, hashedPassword)

  var transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 587,
    secure: false,
    auth: {
      user: process.env.EMAIL_ID,
      pass: process.env.PASSCODE,
    },
    tls: {
      rejectUnauthorized: false,
    },
  });

  var mailOptions = {
    from: process.env.EMAIL_ID,
    to: email,
    subject: "Canteen Management System",
    text:
      "Your registration is successfully completed. Thank you for choosing us.",
  };

  transporter.sendMail(mailOptions, function (error, info) {
    if (error) {
      res.send("Error!");
    } else {
      res.send("Success");
    }
  });

  const token = jwt.sign({ email }, "jwtSecret", {
    expiresIn: 3000,
  });
  return res.send({ auth: true, token: token, email: email });
});



router.post("/signin", async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  const sql = `SELECT email, password FROM users WHERE email = ?`;
  db.all(sql, [email], (err, rows) => {
    if (err) {
      console.log(err.message);
    }else {
      rows.forEach((row) => {
       
        if (row.email == null) {
          return res.send({ auth: false});
        }
        const passwordMatch =bcrypt.compare(password, row.password);
        if (!passwordMatch) {
          return res.send({ auth: false});
        }
        const token = jwt.sign({ email }, "jwtSecret", {
          expiresIn: 3000,
        });
        return res.send({ auth: true, token: token, email: email });
      });
    }
  });
});


router.post("/isLoggedIn", verifyJWT, (req, res) => {
  res.send({ auth: true });
});
module.exports = router;